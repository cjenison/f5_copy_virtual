#!/usr/bin/python
# Home: https://github.com/cjenison/f5_copy_virtual/
# copy_virtual.py
# Author: Chad Jenison (c.jenison at f5.com)
#
# Script that attempts to move a virtual (and all supporting configuration) from one BIG-IP to another

import argparse
import sys
import requests
import json
import getpass
# Note that inside function definitions, paramiko is imported; this is done because paramiko is only needed for SSL cert/key retrieval/sending
# Some people may struggle with use of paramiko module as it has to be built
#import paramiko
from time import sleep

datagroupkeywords = ['equals', 'starts_with', 'ends_with', 'contains']
filestorebasepath = '/config/filestore/files_d'
contentTypeJsonHeader = {'Content-Type': 'application/json'}
destinationAsmPolicySet = set()

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to move a BIG-IP LTM Virtual Server from one BIG-IP to another', epilog="Note that this utility only validates that destination object [e.g. a pool] exists or not on target system; if target object is found, it doesn't modify it")
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--copy', '-c', help='Copy from source to destination BIG-IP (online for both systems)', action='store_true')
mode.add_argument('--get', '-g', help='Get JSON from source and produce file output', action='store_true')
mode.add_argument('--put', '-p', help='Put JSON file input to Destination BIG-IP', action='store_true')
virtual = parser.add_mutually_exclusive_group(required=True)
virtual.add_argument('--virtual', '-v', nargs='*', help='Virtual server(s) to select on source (example: vs-1 or /Public/vs-1)')
virtual.add_argument('--allvirtuals', '-a', help="Select all virtual servers on source", action='store_true')
parser.add_argument('--sourcebigip', '-s', help='IP or hostname of Source BIG-IP Management or Self IP')
parser.add_argument('--destinationbigip', '-d', help='IP or hostname of Destination BIG-IP Management or Self IP')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--file', '-f', help='file for read or write')
parser.add_argument('--ipchange', '-i', help='Prompt user for new Virtual Server IP (Destination)', action='store_true')
#parser.add_argument('--disableonsource', '-ds', help='Disable Virtual Server on Source BIG-IP if successfully copied to destination', action='store_true')
parser.add_argument('--disableondestination', '-dd', help='Disable Virtual Server on Destination BIG-IP as it is copied', action='store_true')
parser.add_argument('--removeonsource', '-remove', help='Remove Virtual Server on Source BIG-IP if successfully copied to destination', action='store_true')
parser.add_argument('--postlog', help='Generate Log File of all POSTs to destination server')
#parser.add_argument('--file', '-f', help='Filename to read or write to')
parser.add_argument('--noprompt', '-n', help='Do not prompt for confirmation of copying operations', action='store_true')

args = parser.parse_args()


# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#adapted from https://devcentral.f5.com/articles/demystifying-icontrol-rest-6-token-based-authentication
def get_auth_token(bigip, username, passwd):
    bip = requests.session()
    bip.verify = False
    payload = {}
    payload['username'] = user
    payload['password'] = passwd
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % bigip
    token = bip.post(authurl, headers=contentTypeJsonHeader, auth=(args.user, passwd), data=json.dumps(payload)).json()['token']['token']
    print ('Got Auth Token: %s' % (token))
    return token

def getConfirmedPassword(bigip, username, password):
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    credentialsValidated = False
    while not credentialsValidated:
        testRequest = bip.get('https://%s/mgmt/tm/sys/' % (bigip))
        if testRequest.status_code == 200:
            credentialsValidated = True
            return password
        elif testRequest.status_code == 401:
            print ('Invalid credentials for user %s' % (user))
            passwordRetryQuery = 'Retry with new password (No to exit)?'
            if query_yes_no(passwordRetryQuery, default="yes"):
                password = getpass.getpass('Re-enter Password for %s' % (user))
                bip.auth = (username, password)
            else:
                print('Exiting due to invalid authentication credentials')
                quit()
        else:
            print('Unexpected Error from test request to validate credentials')
            print('Status Code: %s' % (testRequest.status_code))
            print('Body: %s' % (testRequest.content))
            print('Exiting due to unexpected error condition')
            quit()

def get_folders(bigip, username, password):
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    folders = list()
    folderCollection = bip.get('https://%s/mgmt/tm/sys/folder/' % (bigip)).json()
    for folder in folderCollection['items']:
        folders.append(folder['fullPath'])
    return folders

def get_system_info(bigip, username, password):
    systemInfo = dict()
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    #bip.headers.update(authHeader)
    globalSettings = bip.get('https://%s/mgmt/tm/sys/global-settings/' % (bigip)).json()
    hardware = bip.get('https://%s/mgmt/tm/sys/hardware/' % (bigip)).json()
    partitions = list()
    partitionCollection = bip.get('https://%s/mgmt/tm/auth/partition/' % (bigip)).json()
    for partition in partitionCollection['items']:
        partitions.append(partition['fullPath'])
    systemInfo['partitions'] = partitions
    systemInfo['folders'] = get_folders(bigip, username, password)
    provisionedModules = list()
    provision = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    for module in provision['items']:
        if module.get('level'):
            if module['level'] != 'none':
                provisionedModules.append(module['name'])
    print ('Provisioned Modules: %s' % (provisionedModules))
    systemInfo['provisionedModules'] = provisionedModules
    systemInfo['baseMac'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['baseMac']['description']
    systemInfo['marketingName'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['marketingName']['description']
    version = bip.get('https://%s/mgmt/tm/sys/version/' % (bigip)).json()
    if version.get('nestedStats'):
        systemInfo['version'] = version['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description']
    else:
        volumes = bip.get('https://%s/mgmt/tm/sys/software/volume' % (bigip)).json()
        for volume in volumes['items']:
            if volume.get('active'):
                if volume['active'] == True:
                    systemInfo['version'] = volume['version']
    systemInfo['hostname'] = globalSettings['hostname']
    systemInfo['provision'] = provision
    print ('hostname: %s' % (systemInfo['hostname']))
    print ('version: %s' % (systemInfo['version']))
    systemInfo['provision'] = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    return systemInfo

def get_passphrase(profileFullPath):
    confirmedMatch = False
    while not confirmedMatch:
        passphrase1 = getpass.getpass('Enter passphrase for ssl profile %s:' % (profileFullPath))
        passphrase2 = getpass.getpass('Re-Enter passphrase for ssl profile %s:' % (profileFullPath))
        if passphrase1 == passphrase2:
            confirmedMatch = True
        else:
            print ('Passphrases did not match, please re-enter.')
    return passphrase1

def put_cert_or_key(fullPath, cryptoText, type):
    destinationFileTransferHeaders = {}
    destinationFileTransferHeaders['Content-Type']='text/plain; charset=utf-8'
    destinationFileTransferHeaders['Content-Range']='0-%s/%s' % (len(cryptoText)-1, len(cryptoText))
    upload=destinationbip.post('https://%s/mgmt/shared/file-transfer/uploads/%s' % (args.destinationbigip, fullPath.split("/")[-1]), headers=destinationFileTransferHeaders, data=cryptoText)
    if args.postlog:
        postLog.write('----\nRequest: POST https://%s/mgmt/shared/file-transfer/uploads/%s\n' % (args.destinationbigip, fullPath.split("/")[-1]))
        postLog.write('----\nPayload:\n%s\n----\nResponse:\n%s\n' % (cryptoText, upload.content))
    if upload.status_code == 200:
        print('Upload of %s succeeded' % (type))
    else:
        print('Upload of %s failed - Body: %s' % (upload.content))
    cryptoPostPayload = {}
    cryptoPostPayload['command']='install'
    cryptoPostPayload['name']=fullPath
    cryptoPostPayload['from-local-file']='/var/config/rest/downloads/%s' % (fullPath.split("/")[-1])
    cryptoPost = destinationbip.post('%s/sys/crypto/%s' % (destinationurl_base, type), headers=destinationPostHeaders, data=json.dumps(cryptoPostPayload))
    if args.postlog:
        postLog.write('----\nRequest: POST https://%s/sys/crypto/%s\n' % (args.destinationbigip, type))
        postLog.write('----\nPayload:\n%s\n----\nResponse:\n%s\n' % (json.dumps(cryptoPostPayload), cryptoPost.content))
    if cryptoPost.status_code == 200:
        print('Successfully posted %s: %s to destination BIG-IP' % (type, fullPath))
        if type == 'cert':
            destinationCertSet.add(fullPath)
    else:
        print('Unsuccessful attempt to post %s: %s to destination with JSON: %s' % (type, fullPath, cryptoPostPayload))
        print('Body: %s' % (cryptoPost.content))
    generate_cert_key_set()

def get_virtual(virtualFullPath):
    virtualDict = sourcebip.get('%s/ltm/virtual/%s?expandSubcollections=true' % (sourceurl_base, virtualFullPath.replace("/", "~"))).json()
    if virtualFullPath in sourceAsmVirtualSet:
        virtualConfig.append(get_asm_policy(sourceAsmPolicyIdNameDict[virtualFullPath]['id'], sourceAsmPolicyIdNameDict[virtualFullPath]['name'], sourceAsmPolicyIdNameDict[virtualFullPath]['fullPath']))
    if virtualDict.get('pool'):
        virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/pool/%s' % (virtualDict['pool'].replace("/", "~"))))
    if virtualDict.get('securityLogProfiles'):
        for logProfileReference in virtualDict['securityLogProfilesReference']:
            virtualConfig.append(get_object_by_link(logProfileReference['link']))
    if virtualDict.get('sourceAddressTranslation').get('pool'):
        virtualConfig.append(get_snatpool(virtualDict['sourceAddressTranslation']['pool']))
    virtualPolicies = virtualDict['policiesReference']
    if virtualPolicies.get('items'):
        for policy in virtualPolicies['items']:
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/policy/%s' % (policy['fullPath'].replace("/", "~"))))
    #virtualProfiles = sourcebip.get('%s/ltm/virtual/%s/profiles' % (sourceurl_base, virtualFullPath.replace("/", "~"))).json()
    virtualProfiles = virtualDict['profilesReference']
    if virtualProfiles.get('items'):
        index = 0
        badProfiles = []
        # Modify below code to do this profile removal on apply, not on read
        for profile in virtualProfiles['items']:
            if profile['fullPath'] in sourceAsmBotdefenseProfiles:
                print ('Found Reference to automagic ASM bot-defense profile on virtual - removing (it gets regenerated when applied)')
                badProfiles.append(index)
            elif profile['fullPath'] in sourceApmAccessProfiles:
                print ('***Virtual Server: %s has an APM Access Profile: %s attached; this script doesn\'t support APM currrently, aborting!' % (virtualFullPath, profile))
                quit()
            else:
                if profile.get('nameReference'):
                    virtualConfig.append(get_object_by_link(profile['nameReference']['link']))
                else:
                    virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/profile/%s/%s' % (sourceProfileTypeDict[profile['fullPath']], profile['fullPath'].replace("/", "~"))))
            index += 1
        for profileIndex in badProfiles:
            del virtualProfiles['items'][profileIndex]
    if virtualDict.get('persist'):
        #primaryPersistence = virtualDict['persist']
        #primaryPersistenceFullPath = '/%s/%s' % (virtualDict['persist'][0]['partition'], virtualDict['persist'][0]['name'])
        if 'nameReference' in virtualDict.get('persist'):
            virtualConfig.append(get_object_by_link(virtualDict['persist'][0]['nameReference']['link']))
        else:
            persistenceFullPath = '/%s/%s' % (virtualDict['persist'][0]['partition'], virtualDict['persist'][0]['name'])
            print ('persistenceFullPath: %s' % (persistenceFullPath))
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/persistence/%s/%s' % (sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~"))))
    if virtualDict.get('fallbackPersistence'):
        virtualConfig.append(get_object_by_link(virtualDict['fallbackPersistenceReference']['link']))
    if virtualDict.get('rules'):
        if virtualDict.get('rulesReference'):
            for ruleReference in virtualDict['rulesReference']:
                virtualConfig.append(get_object_by_link(ruleReference['link']))
        else:
            for ruleFullPath in virtualDict['rules']:
                virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/rule/%s' % (ruleFullPath.replace("/", "~"))))
    virtualConfig.append(virtualDict)
    print ('Virtual: %s' % (virtualDict['fullPath']))
    return virtualConfig

def put_virtual(virtualFullPath, virtualConfigArray):
    print('**Processing Virtual: %s Destination BIG-IP: %s' % (virtualFullPath, args.destinationbigip))
    for configObject in virtualConfigArray:
        put_json(configObject['fullPath'], configObject)

def put_json(fullPath, configDict):
    #print('kind: %s' % (configDict['kind']))
    if configDict['kind'] == 'tm:asm:custom:asmpolicy':
        if 'asm' in destinationData['systemInfo']['provisionedModules']:
            if fullPath not in destinationAsmPolicySet:
                put_asm_policy(configDict['policyId'], configDict['policyName'], configDict['xmlPolicy'])
                destinationAsmPolicySet.add(configDict['fullPath'])
            else:
                print('Policy: %s already present on destination BIG-IP' % (fullPath))
        else:
            print('BIG-IP ASM not provisioned on destination BIG-IP')
    elif configDict['kind'] == 'tm:sys:crypto:cert:certstate':
        if fullPath not in destinationCertSet:
            if configDict.get('text'):
                put_cert_or_key(configDict['fullPath'], configDict['text'], 'cert')
    elif configDict['kind'] == 'tm:sys:crypto:key:keystate':
        if fullPath not in destinationKeySet:
            if configDict.get('text'):
                put_cert_or_key(configDict['fullPath'], configDict['text'], 'key')
    elif configDict['kind'] == 'tm:security:bot-defense:asm-profile:asm-profilestate':
        print ('Not putting special ASM bot-defense profile: %s' % (configDict['fullPath']))
    else:
        objectUrl = '%s/%s' % (configDict['selfLink'].rsplit("/", 1)[0].replace("localhost", args.destinationbigip, 1), configDict['fullPath'].replace("/", "~"))
        postUrl = configDict['selfLink'].rsplit("/", 1)[0].replace("localhost", args.destinationbigip, 1)
        print ('objectUrl: %s' % (objectUrl))
        destinationObjectGet = destinationbip.get(objectUrl)
        if destinationObjectGet.status_code == 200:
            print('config object: %s already on destination; leaving in place' % (fullPath))
        elif destinationObjectGet.status_code == 404:
            if configDict['kind'] == 'tm:ltm:virtual:virtualstate':
                if args.ipchange:
                    changeDestination = 'Source Virtual Server Destination: %s - port: %s mask: %s - Change?' % (configDict['destination'].split("/")[2].rsplit(":", 1)[0], configDict['destination'].split("/")[2].rsplit(":", 1)[1], configDict['mask'])
                    if query_yes_no(changeDestination, default="yes"):
                        newDestination = obtain_new_vs_destination(configDict['destination'].split("/")[2].rsplit(":", 1)[0], configDict['destination'].split("/")[2].rsplit(":", 1)[1], configDict['mask'])
                        destinationPartition = configDict['destination'].split("/")[1]
                        configDict['destination'] = '/%s/%s:%s' % (destinationPartition, newDestination['ip'], newDestination['port'])
                        configDict['mask'] = newDestination['mask']
                        print ('New Destination: %s - port: %s mask: %s' % (newDestination['ip'], newDestination['port'], newDestination['mask']))
                if args.disableondestination:
                    if configDict.get('enabled'):
                        del configDict['enabled']
                    configDict['disabled'] = True
                ### Observed problems posting this to Old BIG-IP; Investigate
                if configDict.get('serviceDownImmediateAction'):
                    del configDict['serviceDownImmediateAction']
                if configDict.get('rulesReference'):
                    del configDict['rulesReference']
                if configDict.get('policiesReference').get('items') and downgrade:
                    print('Downgrading Local Traffic Policies can be problematic; proceeding with best effort')
            elif configDict['kind'] == 'tm:ltm:pool:poolstate':
                for member in configDict['membersReference']['items']:
                    if destinationShortVersion < 11.6:
                        del member['fqdn']
                    ## Not sure why we need to delete this property, but we do
                    try:
                        del member['session']
                        del member['state']
                        del member['ephemeral']
                    except:
                        pass
            elif configDict['kind'] == 'tm:ltm:snatpool:snatpoolstate':
                if configDict.get('membersReference'):
                    del configDict['membersReference']
            elif configDict['kind'] == 'tm:ltm:policy:policystate':
                if destinationShortVersion >= 12.1:
                    configDict['subPath']='Drafts'
                    configDict['fullPath']='/%s/Drafts/%s' % (configDict['partition'], configDict['name'])
                if downgrade:
                    if configDict.get('lastModified'):
                        del configDict['lastModified']
                    if destinationShortVersion < 12.1:
                        try:
                            del configDict['status']
                            del configDict['references']
                        except KeyError, e:
                            pass
                    for rule in configDict['rulesReference']['items']:
                        print ('Rule: %s' % (rule['name']))
                        for action in rule['actionsReference']['items']:
                            print ('Action: %s' % (action['name']))
                            for actionProperty in ['expirySecs', 'length', 'timeout', 'offset', 'connection', 'shutdown']:
                                if downgrade and float(destinationShortVersion) < 12.1:
                                    try:
                                        del action[actionProperty]
                                        print('Apparent use of %s in policy rule action; unable to downgrade' % (actionProperty))
                                    except KeyError, e:
                                        pass
                    print ('Attempting Downgrading of policy')
                    #print('Moving policies to older software revisions is not supported; policy: %s not copied' % (fullPath))
                    #return
            elif configDict['kind'] == 'tm:ltm:profile:http:httpstate':
                if downgrade:
                    if configDict.get('proxyType') == 'reverse':
                        del configDict['explicitProxy']
                    if configDict.get('enforcement').get('knownMethods'):
                        del configDict['enforcement']['knownMethods']
                    if configDict.get('hsts'):
                        del configDict['hsts']
            elif configDict['kind'] == 'tm:ltm:profile:tcp:tcpstate':
                if downgrade:
                    # Need to Sort These Problem Properties by which version they showed up in
                    tcpDowngradeProperties = ['nagle', 'autoReceiveWindowSize', 'ratePaceMaxRate', 'fastOpen', 'fastOpenCookieExpiration', 'cmetricsCacheTimeout', 'autoSendBufferSize', 'synCookieWhitelist', 'hardwareSynCookie', 'ipTtlMode', 'ipTtlV4', 'ipTtlV6', 'autoProxyBufferSize', 'ipDfMode', 'earlyRetransmit', 'tailLossProbe', 'rexmtThresh', 'pushFlag', 'enhancedLossRecovery', 'synCookieEnable', 'finWait_2Timeout']
                    mptcpProperties = ['mpctp', 'mptcpCsum', 'mptcpCsumVerify', 'mptcpDebug', 'mptcpDebug', 'mptcpFallback', 'mpctcpFastjoin', 'mptcpIdleTimeout', 'mptcpJoinMax', 'mptcpMakeafterbreak', 'mptcpNojoindssack', 'mptcpRtomax', 'mptcpRxmitmin', 'mptcpSubflowmax', 'mptcpTimeout']
                    allBadProperties = tcpDowngradeProperties + mptcpProperties
                    for property in allBadProperties:
                        try:
                            del configDict[property]
                        except:
                            pass
            elif configDict['kind'] == 'tm:ltm:profile:client-ssl:client-sslstate':
                ### FIX BELOW TO Handle CertkeyChain properly
                if configDict.get('certKeyChain'):
                    del configDict['certKeyChain']
                if configDict['cert'] not in destinationCertSet or configDict['key'] not in destinationKeySet:
                    print('cert: %s and/or key: %s missing on destination - altering cert/key references to default.crt/default.key')
                    configDict['cert'] = '/Common/default.crt'
                    configDict['key'] = '/Common/default.crt'
                if downgrade:
                    sslVersionProperties = dict()
                    sslVersionProperties['13.1'] = ['c3dOcsp', 'sslC3d', 'c3dDropUnknownOcspStatus']
                    sslVersionProperties['13.0'] = ['cipherGroup', 'cipherGroupReference', 'bypassOnClientCertFail', 'bypassOnHandshakeAlert', 'notifyCertStatusToVirtualServer']
                    sslVersionProperties['12.1'] = ['maxActiveHandshakes', 'allowDynamicRecordSizing', 'maximumRecordSize']
                    sslVersionProperties['12.0'] = ['sessionMirroring', 'allowExpiredCrl', 'sessionTicketTimeout']
                    sslVersionProperties['11.6'] = ['ocspStapling', 'peerNoRenegotiateTimeout', 'maxRenegotiationsPerMinute', 'maxAggregateRenegotiationPerMinute', 'proxySslPassthrough']
                    for version in sslVersionProperties.keys():
                        if destinationShortVersion < float(version):
                            for property in sslVersionProperties[version]:
                                try:
                                    del configDict[property]
                                except:
                                    pass
                if configDict.get('passphrase'):
                    print('Source client-ssl profile: %s contains encrypted passphrase; need to re-obtain passphrase')
                    print('**Note: passphrases are encrypted on BIG-IP using Secure Vault technology')
                    print('**Note: passphrase will be submitted via iControl REST, but will be immediately encrypted on BIG-IP')
                    configDict['passphrase'] = get_passphrase(configDict['fullPath'])
            print ('Posting to: %s' % (postUrl))
            destinationObjectPost = destinationbip.post(postUrl, headers=destinationPostHeaders, data=json.dumps(configDict))
            if args.postlog:
                postLog.write('----\nRequest: POST %s' % (postUrl))
                postLog.write('----\nPayload:\n%s\n----\nResponse:\n%s\n' % (json.dumps(configDict), destinationObjectPost.content))
            if destinationObjectPost.status_code == 200:
                if configDict['kind'] == 'tm:ltm:policy:policystate' and destinationShortVersion >= 12.1:
                    draftFullPath = '/%s/Drafts/%s' % (configDict['partition'], configDict['name'])
                    publishCommand = {'command':'publish', 'name': draftFullPath}
                    publishPolicy = destinationbip.post('%s/ltm/policy/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(publishCommand))
                    if publishPolicy.status_code == 200:
                        print ('Successully Published Policy: %s' % (fullPath))
                    else:
                        print ('Unsuccessful Publish of Policy: %s' % (fullPath))
                        print ('Status Code: - Body: %s' % (publishPolicy.status_code, publishPolicy.content))
                print ('Successfully Posted Object: %s to URL: %s' % (fullPath, postUrl))
            else:
                if configDict['kind'] == 'tm:ltm:profile:client-ssl:client-sslstate' and destinationObjectPost.status_code == 400 and 'Error reading key PEM' in destinationObjectPost.content:
                    passphraseWrongString = 'Passphrase incorrect for key: %s in client-ssl profile: %s - Retry Password Entry?' % (configDict['key'], fullPath)
                    if query_yes_no(passphraseWrongString, default="yes"):
                        put_json(fullPath, configDict)
                print ('Unsuccessful Post of Object: %s to URL: %s' % (fullPath, postUrl))
                print ('Payload: %s' % (json.dumps(configDict)))
                print ('Status Code: %s - Body: %s' % (destinationObjectPost.status_code, destinationObjectPost.content))

def obtain_new_vs_destination(destination, port, mask):
    changeDestination = 'Destination: %s - Change?' % (destination)
    if query_yes_no(changeDestination, default="yes"):
        inputChecked = False
        while not inputChecked:
            newDestination = raw_input("Enter New Destination (only network/IP [e.g. 128.200.1.0] without mask suffix): ")
            ## Add input validation code
            inputChecked = True
    else:
        newDestination = destination

    changePort = 'Port: %s - Change?' % (port)
    if query_yes_no(changePort, default="yes"):
        inputChecked = False
        while not inputChecked:
            newPort = raw_input("Enter New Destination Port: ")
            ## Add input validation code
            inputChecked = True
    else:
        newPort = port

    changeMask = 'Mask: %s - Change?' % (mask)
    if query_yes_no(changeMask, default="yes"):
        inputChecked = False
        while not inputChecked:
            newMask = raw_input("Enter New Destination Mask (in dotted quad form for IPv4 [e.g. 255.255.255.0]): ")
            ## Add input validation code
            inputChecked = True
    else:
        newMask = mask

    destination = {'ip': newDestination, 'port':newPort, 'mask':newMask}
    return destination

def get_cert_or_key_via_sftp(cryptoFullPath, type):
    import paramiko
    sourcessh = paramiko.SSHClient()
    sourcessh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sourcessh.connect(args.sourcebigip, username=args.user, password=passwd, allow_agent=False)
    sourcesftp = sourcessh.open_sftp()
    filestore_basepath = '/config/filestore/files_d'
    cryptoPartition = cryptoFullPath.split(("/"))[1]
    if type == 'cert':
        cryptoFilestorePath = '%s/%s_d/certificate_d/' % (filestore_basepath, cryptoPartition)
    elif type == 'key':
        cryptoFilestorePath = '%s/%s_d/certificate_key_d/' % (filestore_basepath, cryptoPartition)
    sourcesftp.chdir(cryptoFilestorePath)
    sourceCryptoFiles = sourcesftp.listdir()
    for file in sourceCryptoFiles:
        if file.replace(":", "/").startswith(cryptoFullPath):
            cryptoFilename = file
    cryptoFileRead = sourcesftp.open('%s/%s' % (cryptoFilestorePath, cryptoFilename), 'r')
    cryptoFile = cryptoFileRead.read()
    cryptoFileRead.close()
    return cryptoFile


def get_cert_or_key(cryptoFullPath, type):
    isChainCert = False
    if type == 'chaincert':
        isChainCert = True
        type = 'cert'
    cryptoDict = sourcebip.get('%s/sys/crypto/%s/%s' % (sourceurl_base, type, cryptoFullPath.replace("/", "~"))).json()
    ## below code is to handle a bug in 11.5.x iControl REST (path prefix in front of filename isn't handled properly)
    if cryptoDict.get('code') == 404:
        cryptoDict = sourcebip.get('%s/sys/crypto/%s/' % (sourceurl_base, type)).json()
        for cryptoObject in cryptoDict['items']:
            if cryptoObject['fullPath'] == cryptoFullPath:
                cryptoDict = cryptoObject
                break
    filestoreBasePath = '/config/filestore/files_d'
    if type == 'cert':
        partitionFolder = '%s/%s_d/certificate_d/' % (filestoreBasePath, cryptoFullPath.split("/")[1])
    elif type == 'key':
        partitionFolder = '%s/%s_d/certificate_key_d/' % (filestoreBasePath, cryptoFullPath.split("/")[1])
    if not isChainCert:
        catCryptoPayload = { 'command' : 'run', 'utilCmdArgs': '-c \'cat %s%s*\'' % (partitionFolder, cryptoFullPath.replace("/", ":"))}
        cryptoCatRaw = sourcebip.post('%s/util/bash' % (sourceurl_base), headers=sourcePostHeaders, data=json.dumps(catCryptoPayload))
        cryptoCat = sourcebip.post('%s/util/bash' % (sourceurl_base), headers=sourcePostHeaders, data=json.dumps(catCryptoPayload)).json()
        cryptoDict['text'] = cryptoCat['commandResult']
    else:
        cryptoDict['text'] = get_cert_or_key_via_sftp(cryptoFullPath, type)
        print ('Chain Cert: %s' % (cryptoDict['text']))
    print ('Getting object: %s' % (cryptoDict['selfLink'].replace("https://localhost/mgmt/tm", "", 1).split("?")[0]))
    print('Getting %s: %s' % (type, cryptoFullPath))
    return cryptoDict

def get_object_by_link(link):
    print ('Getting object: %s' % (link.replace("https://localhost/mgmt/tm", "", 1).split("?")[0]))
    if '/ltm/pool/' in link or '/ltm/policy/' in link:
        objectDict = sourcebip.get('%s?expandSubcollections=true' % (link.replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    else:
        objectDict = sourcebip.get('%s' % (link.replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    if objectDict.get('defaultsFrom') and objectDict.get('defaultsFrom') != 'none':
        print ("Detected Profile Inheritance; fetching %s/%s" % (link.rsplit("/", 1)[0], objectDict['defaultsFrom'].replace("/", "~")))
        virtualConfig.append(get_object_by_link('%s/%s' % (link.rsplit("/", 1)[0], objectDict['defaultsFrom'].replace("/", "~"))))
    if objectDict['kind'] == 'tm:ltm:profile:client-ssl:client-sslstate':
        if objectDict.get('cipherGroupReference'):
            virtualConfig.append(get_object_by_link(objectDict['cipherGroupReference']['link']))
        if objectDict.get('certKeyChain'):
            for certKey in objectDict['certKeyChain']:
                virtualConfig.append(get_cert_or_key(certKey['key'], 'key'))
                virtualConfig.append(get_cert_or_key(certKey['cert'], 'cert'))
                if certKey.get('chain'):
                    print ('Chain Cert Referenced: Not retrieving chain cert bundle - Please ensure installation of chain cert on destination')
                    #if certKey['chain'] != "none":
                    #    virtualConfig.append(get_cert_or_key(certKey['chain'], 'chaincert'))
        else:
            print('Getting client-ssl profile: %s - Cert: %s - Key: %s' % (objectDict['name'], objectDict['cert'], objectDict['key']))
            cert = get_cert_or_key(objectDict['cert'], 'cert')
            key = get_cert_or_key(objectDict['key'], 'key')
            virtualConfig.append(key)
            virtualConfig.append(cert)
    elif objectDict['kind'] == 'tm:ltm:cipher:group:groupstate':
        for ruleGroup in ['allow', 'exclude', 'require']:
            for ruleItem in objectDict.get(ruleGroup):
                virtualConfig.append(get_object_by_link(ruleItem['nameReference']['link']))
    elif objectDict['kind'] == 'tm:ltm:policy:policystate':
        for rule in objectDict['rulesReference']['items']:
            for item in rule['actionsReference']['items']:
                if item.get('pool'):
                    print ('Detected a Policy Action selecting pool: %s' % (item['pool']))
                    virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/pool/%s' % (item['pool'].replace("/", "~"))))
        virtualConfig.append(get_policy_strategy(objectDict['strategy']))
    elif objectDict['kind'] == 'tm:ltm:persistence:universal:universalstate':
        if objectDict.get('rule') and not objectDict.get('rule') == 'none':
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/rule/%s' % (objectDict['rule'].replace("/", "~"))))
    elif objectDict['kind'] == 'tm:ltm:rule:rulestate':
        datagroupHits = set()
        for datagroup in sourceDatagroupSet:
            for keyword in datagroupkeywords:
                if datagroup.split("/")[1] == 'Common':
                    dgName = datagroup.split("/")[2]
                    searchString = '%s %s' % (keyword, dgName)
                    if searchString in objectDict['apiAnonymous']:
                        datagroupHits.add(datagroup)
                dgName = datagroup
                searchString = '%s %s' % (keyword, dgName)
                if searchString in objectDict['apiAnonymous']:
                    datagroupHits.add(datagroup)
        for matchedDatagroup in datagroupHits:
            print('Rule: %s may reference Datagroup: %s' % (objectDict['fullPath'], matchedDatagroup))
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/data-group/%s/%s' % (sourceDatagroupTypeDict[matchedDatagroup], matchedDatagroup.replace("/", "~"))))
            #virtualConfig.append(get_datagroup(matchedDatagroup))
        ifileHits = set()
        iRulePoolMatches = set()
        # Implement code to check for "pool <poolname>" in iRule code to identify pool dependencies
        for pool in sourcePoolSet:
            if 'pool %s' % pool in objectDict['apiAnonymous'] or 'pool %s' % pool.split("/")[-1] in objectDict['apiAnonymous']:
                print ('Got an iRule match for pool: %s on rule: %s' % (objectDict['fullPath'], pool))
                virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/pool/%s' % (pool.replace("/", "~"))))
        for ifile in sourceIfileSet:
            if ifile.split("/")[1] == 'Common':
                ifilename = ifile.split("/")[2]
                searchString = 'ifile get \"%s\"' % (ifilename)
                if searchString in objectDict['apiAnonymous']:
                    ifileHits.add(ifile)
                    print ('Detected a possible iFile dependency in iRule: %s for ifile: %s [Please resolve this manually]' % (objectDict['fullPath'], ifile))

    elif objectDict['kind'] == "tm:ltm:pool:poolstate":
        if objectDict.get('monitor'):
            for monitor in objectDict['monitor'].strip().split(' and '):
                virtualConfig.append(get_monitor(monitor))
        if objectDict.get('membersReference').get('items'):
            for member in objectDict['membersReference']['items']:
                if member['monitor'] != 'default':
                    for monitor in member['monitor'].strip().split(' and '):
                        virtualConfig.append(get_monitor(monitor))
    return objectDict

def get_object(profileReference):
    objectDict = sourcebip.get('%s' % (profileReference['nameReference']['link'].replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    print('Profile: %s' % (objectDict['fullPath']))
    return objectDict

#def get_datagroup(datagroupFullPath):
#    datagroupDict = sourcebip.get('%s/ltm/data-group/%s/%s' % (sourceurl_base, sourceDatagroupTypeDict[datagroupFullPath], datagroupFullPath.replace("/", "~"))).json()
#    return datagroupDict

#def get_persistence(persistenceFullPath):
#    persistenceDict = sourcebip.get('%s/ltm/persistence/%s/%s' % (sourceurl_base, sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~"))).json()
#    return persistenceDict

def get_monitor(monitorFullPath):
    monitorDict = sourcebip.get('%s/ltm/monitor/%s/%s' % (sourceurl_base, sourceMonitorTypeDict[monitorFullPath], monitorFullPath.replace("/", "~"))).json()
    return monitorDict

def get_snatpool(snatpoolFullPath):
    snatpoolDict = sourcebip.get('%s/ltm/snatpool/%s' % (sourceurl_base, snatpoolFullPath.replace("/", "~"))).json()
    return snatpoolDict

#def get_policy(policyFullPath):
#    policyDict = sourcebip.get('%s/ltm/policy/%s?expandSubcollections=true' % (sourceurl_base, policyFullPath.replace("/", "~"))).json()
#    virtualConfig.append(get_policy_strategy(policyDict['strategy']))
#    return policyDict

def get_policy_strategy(policyStrategyFullPath):
    policyStrategyDict = sourcebip.get('%s/ltm/policy-strategy/%s' % (sourceurl_base, policyStrategyFullPath.replace("/", "~"))).json()
    return policyStrategyDict

def generate_dest_asm_policy_set():
    destinationAsmPolicies = destinationbip.get('%s/asm/policies/' % (destinationurl_base)).json()
    for policy in destinationAsmPolicies['items']:
        #print('policy name: %s; policy fullpath: %s' % (policy['name'], policy['fullPath']))
        destinationAsmPolicySet.add(policy['fullPath'])

def generate_cert_key_set():
    destinationCerts = destinationbip.get('%s/sys/crypto/cert/' % (destinationurl_base)).json()
    for cert in destinationCerts['items']:
        destinationCertSet.add(cert['fullPath'])
    destinationKeys = destinationbip.get('%s/sys/crypto/key/' % (destinationurl_base)).json()
    for key in destinationKeys['items']:
        destinationKeySet.add(key['fullPath'])

def put_asm_policy(policyId, policyName, xmlPolicy):
    #policyUpload = destinationbip.post('https://%s/mgmt/tm/asm/file-transfer/uploads/%s.xml' % (args.destinationbigip, policyName), headers=fileUploadHeader, data=xmlPolicy )
    #print ('policyUpload Response: %s' % (policyUpload.content))
    #print ('policyUploadResponse: %s' % (policyUpload.content))
    ### Add a check to see that ASM is provisioned
    if 'asm' in destinationData['systemInfo']['provisionedModules']:
        print ('we have ASM')
        policyImportPayload = {'file': xmlPolicy, 'status': 'NEW' }
        importPolicyTask = destinationbip.post('%s/asm/tasks/import-policy' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(policyImportPayload)).json()
        if args.postlog:
            postLog.write('----\nRequest: POST %s/asm/tasks/import-policy\n' % (destinationurl_base))
            postLog.write('----\nPayload:\nASM Policy XML (trimmed to 100 bytes)\n%s\n----Response:\n%s\n' % (xmlPolicy[0:99], json.dumps(importPolicyTask)))
        taskId = importPolicyTask['id']
        print ('upload taskId: %s' % (taskId))
        taskDone = False
        while not taskDone:
            task = destinationbip.get('%s/asm/tasks/import-policy/%s' % (destinationurl_base, taskId)).json()
        if task['status'] == 'COMPLETED':
            taskDone = True
        else:
            print ('Policy Import Task Not Done - sleeping 2 seconds')
            sleep(2)
        print ('taskId: %s' % (taskId))
        #print ('importPolicyResponse: %s' % (importPolicyTask.content))
    else:
        print ('Destination BIG-IP does not have BIG-IP provisioned')

def get_asm_policy(policyId, policyName, policyFullPath):
    policyDict={ 'policyId': policyId, 'policyName': policyName, 'kind':'tm:asm:custom:asmpolicy', 'fullPath': policyFullPath }
    exportPolicyTaskPayload = dict()
    policyLink = {'link': 'https://localhost/mgmt/tm/asm/policies/%s' % policyId}
    exportPolicyTaskPayload['filename']='%s.xml' % (policyId)
    exportPolicyTaskPayload['policyReference']=policyLink
    policyTaskPost = sourcebip.post('https://%s/mgmt/tm/asm/tasks/export-policy' % (args.sourcebigip), headers=sourcePostHeaders, data=json.dumps(exportPolicyTaskPayload)).json()
    taskId = policyTaskPost['id']
    taskDone = False
    while not taskDone:
        task = sourcebip.get('https://%s/mgmt/tm/asm/tasks/export-policy/%s' % (args.sourcebigip, taskId)).json()
        if task['status'] == 'COMPLETED':
            taskDone = True
        else:
            print ('Policy Export Task Not Done - sleeping 2 seconds')
            sleep(2)
    retrieveXmlPolicy = sourcebip.get('https://%s/mgmt/tm/asm/file-transfer/downloads/%s.xml' % (args.sourcebigip, policyId))
    #with open('%s.xml' % (policyId), 'w') as xmlOut:
    #    xmlOut.write(retrieveXmlPolicy.content)
    policyDict['xmlPolicy']=retrieveXmlPolicy.content
    return policyDict

def create_folder(fullPath):
    createFolderPayload = {'name' : fullPath}
    folderPost = destinationbip.post('%s/sys/folder/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(createFolderPayload))
    if args.postlog:
        postLog.write('----\nRequest: POST %s\n' % ('%s/sys/folder/' % (destinationurl_base)))
        postLog.write('----\nPayload:\n%s\n----\nResponse:\n%s\n' % (json.dumps(createFolderPayload), folderPost.content))
    if folderPost.status_code == 200:
        print('Created folder: %s' % (fullPath))
    else:
        print('Creation of folder: %s - FAILED' % (fullPath))
        print('Response: %s' % (folderPost.content))

def create_partition(name):
    createPartitionPayload = {'name' : name}
    partitionPost = destinationbip.post('%s/auth/partition/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(createPartitionPayload))
    if args.postlog:
        postLog.write('----\nRequest: POST %s\n' % ('%s/auth/partition/' % (destinationurl_base)))
        postLog.write('----\nPayload:\n%s\n----\nResponse:\n%s\n' % (json.dumps(createPartitionPayload), partitionPost.content))
    if partitionPost.status_code == 200:
        print('Created partition: %s' % (name))
    else:
        print('Creation of partition: %s - FAILED' % (name))
        print('Response: %s' % (partitionPost.content))

if (args.get or args.put) and not args.file:
    print ('When mode --get or --put is used; a --file argument is required; exiting...')
    quit()
user = args.user
passwd = getpass.getpass('Enter Password for %s:' % (user))

requests.packages.urllib3.disable_warnings()


if args.destinationbigip and (args.copy or args.put):
    destinationurl_base = ('https://%s/mgmt/tm' % (args.destinationbigip))
    destinationbip = requests.session()
    destinationbip.verify = False
    destpasswd = getConfirmedPassword(args.destinationbigip, user, passwd)
    #destinationData = get_system_info(args.destinationbigip, args.user, destpasswd)
    destinationData = {}
    destinationData['systemInfo'] = get_system_info(args.destinationbigip, args.user, destpasswd)
    destinationVersion = destinationData['systemInfo']['version']
    destinationShortVersion = float('%s.%s' % (destinationData['systemInfo']['version'].split(".")[0], destinationData['systemInfo']['version'].split(".")[1]))
    destinationAuthHeader = {}
    if destinationShortVersion >= 11.6:
        destinationAuthToken = get_auth_token(args.destinationbigip, args.user, destpasswd)
        destinationAuthHeader['X-F5-Auth-Token']=destinationAuthToken
        destinationbip.headers.update(destinationAuthHeader)
    else:
        destinationbip.auth = (args.user, destpasswd)
    print('Destination BIG-IP Hostname: %s' % (destinationData['systemInfo']['hostname']))
    print('Destination BIG-IP Software: %s' % (destinationData['systemInfo']['version']))
    destinationPostHeaders = destinationAuthHeader
    destinationPostHeaders.update(contentTypeJsonHeader)
    if 'asm' in destinationData['systemInfo']['provisionedModules']:
        generate_dest_asm_policy_set()
    destinationVirtualSet = set()
    destinationVirtuals = destinationbip.get('%s/ltm/virtual/' % (destinationurl_base)).json()
    if destinationVirtuals.get('items'):
        for virtual in destinationVirtuals['items']:
            destinationVirtualSet.add(virtual['fullPath'])
    destinationCertSet = set()
    destinationKeySet = set()
    generate_cert_key_set()



if args.sourcebigip and (args.copy or args.get):
    sourceurl_base = ('https://%s/mgmt/tm' % (args.sourcebigip))
    sourcebip = requests.session()
    sourcebip.verify = False
    sourcepasswd = getConfirmedPassword(args.sourcebigip, user, passwd)
    #sourceSystemInfo = get_system_info(args.sourcebigip, args.user, sourcepasswd)
    sourceData = {}
    sourceData['systemInfo'] = get_system_info(args.sourcebigip, args.user, sourcepasswd)
    sourceVersion = sourceData['systemInfo']['version']
    sourceShortVersion = float('%s.%s' % (sourceData['systemInfo']['version'].split(".")[0], sourceData['systemInfo']['version'].split(".")[1]))
    sourceAuthHeader = {}
    if sourceShortVersion >= 11.6:
        sourceAuthToken = get_auth_token(args.sourcebigip, args.user, sourcepasswd)
        sourceAuthHeader['X-F5-Auth-Token']=sourceAuthToken
        sourcebip.headers.update(sourceAuthHeader)
    else:
        sourcebip.auth = (args.user, sourcepasswd)
    print('Source BIG-IP Hostname: %s' % (sourceData['systemInfo']['hostname']))
    print('Source BIG-IP Software: %s' % (sourceData['systemInfo']['version']))
    if 'afm' in sourceData['systemInfo']['provisionedModules']:
        afmConfirm = ('***WARNING*** BIG-IP AFM is provisioned and script does not support AFM configuration; Proceed?')
        if query_yes_no(afmConfirm, default="no"):
            print('Proceeding; unpredictable results may occur')
        else:
            print('Exiting due to AFM')
            quit()
    if 'apm' in sourceData['systemInfo']['provisionedModules']:
        apmConfirm = ('***WARNING*** BIG-IP APM is provisioned and script does not support APM configuration; Proceed?')
        if query_yes_no(apmConfirm, default="no"):
            print('Proceeding; unpredictable results may occur')
        else:
            print('Exiting due to APM')
            quit()
    sourcePostHeaders = sourceAuthHeader
    sourcePostHeaders.update(contentTypeJsonHeader)

    # WRAP this in a conditional based on "sourceShortVersion" once I figure out whether profile references in virtual server include nameReference appeared in what version
    sourceProfileTypeDict = dict()
    sourceProfiles = sourcebip.get('%s/ltm/profile/' % (sourceurl_base)).json()
    for profile in sourceProfiles['items']:
        typeUrlFragment = profile['reference']['link'].split("/")[-1].split("?")[0]
        profileTypeCollection = sourcebip.get('%s/ltm/profile/%s' % (sourceurl_base, typeUrlFragment)).json()
        if profileTypeCollection.get('items'):
            for profile in profileTypeCollection['items']:
                sourceProfileTypeDict[profile['fullPath']] = typeUrlFragment

    sourceApmAccessProfiles = set()
    apmAccessProfiles = sourcebip.get('%s/mgmt/tm/apm/profile/access' % (sourceurl_base))
    if apmAccessProfiles.status_code == 200:
        apmAccessProfilesDict = json.loads(apmAccessProfiles.content)
        for profile in apmAccessProfiles['items']:
            sourceApmAccesProfiles.add(profile['fullPath'])

    sourceAsmBotdefenseProfiles = set()
    botdefenseProfiles = sourcebip.get('%s/security/bot-defense/asm-profile/' % (sourceurl_base))
    if botdefenseProfiles.status_code == 200:
        botdefenseProfilesDict = json.loads(botdefenseProfiles.content)
        for profile in botdefenseProfilesDict['items']:
            sourceAsmBotdefenseProfiles.add(profile['fullPath'])

    sourcePersistenceTypeDict = dict()
    sourcePersistenceProfiles = sourcebip.get('%s/ltm/persistence/' % (sourceurl_base)).json()
    for persistenceProfile in sourcePersistenceProfiles['items']:
        typeUrlFragment = persistenceProfile['reference']['link'].split("/")[-1].split("?")[0]
        persistenceProfileTypeCollection = sourcebip.get('%s/ltm/persistence/%s' % (sourceurl_base, typeUrlFragment)).json()
        if persistenceProfileTypeCollection.get('items'):
            for persistenceProfile in persistenceProfileTypeCollection['items']:
                sourcePersistenceTypeDict[persistenceProfile['fullPath']] = typeUrlFragment

    sourceMonitorTypeDict = dict()
    sourceMonitors = sourcebip.get('%s/ltm/monitor/' % (sourceurl_base)).json()
    for monitor in sourceMonitors['items']:
        typeUrlFragment = monitor['reference']['link'].split("/")[-1].split("?")[0]
        monitorTypeCollection = sourcebip.get('%s/ltm/monitor/%s' % (sourceurl_base, typeUrlFragment)).json()
        if monitorTypeCollection.get('items'):
            for monitor in monitorTypeCollection['items']:
                sourceMonitorTypeDict[monitor['fullPath']] = typeUrlFragment

    sourceVirtualDict = dict()
    sourceVirtualSet = set()
    sourceVirtuals = sourcebip.get('%s/ltm/virtual/' % (sourceurl_base)).json()
    if sourceVirtuals.get('items'):
        for virtual in sourceVirtuals['items']:
            sourceVirtualDict[virtual['name']] = virtual['fullPath']
            sourceVirtualSet.add(virtual['fullPath'])

    sourceAsmVirtualSet = set()
    sourceAsmPolicyIdNameDict = dict()
    sourceAsmPolicies = sourcebip.get('%s/asm/policies' % (sourceurl_base))
    if sourceAsmPolicies.status_code == 200:
        sourceAsmPoliciesDict = json.loads(sourceAsmPolicies.content)
        for policy in sourceAsmPoliciesDict['items']:
            if policy.get('virtualServers'):
                for virtual in policy['virtualServers']:
                   sourceAsmVirtualSet.add(virtual)
                   sourceAsmPolicyIdNameDict[virtual]= {'id': policy['id'], 'name':policy['name'], 'fullPath':policy['fullPath']}

    sourceIfileSet = set()
    sourceIfiles = sourcebip.get('%s/ltm/ifile/' % (sourceurl_base)).json()
    if sourceIfiles.get('items'):
        for ifile in sourceIfiles['items']:
            sourceIfileSet.add(ifile['fullPath'])
    #print('sourceIfileSet: %s' % (sourceIfileSet))

    sourcePoolSet = set()
    sourcePools = sourcebip.get('%s/ltm/pool/' % (sourceurl_base)).json()
    if sourcePools.get('items'):
        for pool in sourcePools['items']:
            sourcePoolSet.add(pool['fullPath'])

    sourceDatagroupSet = set()
    sourceDatagroupTypeDict = dict()
    sourceInternalDatagroups = sourcebip.get('%s/ltm/data-group/internal/' % (sourceurl_base)).json()
    if sourceInternalDatagroups.get('items'):
        for datagroup in sourceInternalDatagroups['items']:
            sourceDatagroupSet.add(datagroup['fullPath'])
            sourceDatagroupTypeDict[datagroup['fullPath']] = 'internal'

    sourceExternalDatagroups = sourcebip.get('%s/ltm/data-group/external/' % (sourceurl_base)).json()
    if sourceExternalDatagroups.get('items'):
        for datagroup in sourceExternalDatagroups['items']:
            sourceDatagroupSet.add(datagroup['fullPath'])
            sourceDatagroupTypeDict[datagroup['fullPath']] = 'external'
    #print('sourceDatagroupTypeDict: %s' % (sourceDatagroupTypeDict))

virtualsList = []
downgrade = False

if args.copy or args.get:
    sourceData['kind'] = 'f5:unofficial:virtual:copy:utility:data'
    if args.virtual is not None:
        virtuals = args.virtual
    elif args.allvirtuals:
        virtuals = sourceVirtualSet
    for virtual in virtuals:
        sourceVirtual = dict()
        virtualConfig = []
        if virtual in sourceVirtualSet:
            print ('Processing Virtual: %s' % (virtual))
            sourceVirtual['virtualFullPath'] = virtual
            sourceVirtual['virtualListConfig'] = get_virtual(virtual)
            virtualsList.append(sourceVirtual)
        elif virtual in sourceVirtualDict.keys():
            print ('Virtual(s) to copy: %s' % (sourceVirtualDict[virtual]))
            sourceVirtual['virtualFullPath'] = sourceVirtualDict[virtual]
            sourceVirtual['virtualListConfig'] = get_virtual(sourceVirtualDict[virtual])
            virtualsList.append(sourceVirtual)
        else:
            print ('Virtual Argument: %s not found; skipping' % (virtual))
    sourceData['virtuals'] = virtualsList
    if args.get:
        with open(args.file, 'w') as fileOut:
            json.dump(sourceData, fileOut, indent=4, sort_keys=True)



if args.copy or args.put:
    if args.postlog:
        postLog = open(args.postlog, 'w')
    if args.put:
        print('Reading Virtual Config Data from file: %s' % (args.put))
        with open(args.file, 'r') as fileIn:
            sourceData = json.load(fileIn)
    elif args.copy:
        print ('Copy Mode: beginning copy of virtuals to destination')
    sourceShortVersion = float('%s.%s' % (sourceData['systemInfo']['version'].split(".")[0], sourceData['systemInfo']['version'].split(".")[1]))
    destinationShortVersion = float('%s.%s' % (destinationData['systemInfo']['version'].split(".")[0], destinationData['systemInfo']['version'].split(".")[1]))
    if sourceShortVersion > destinationShortVersion:
        print ('Houston We Have a Problem')
        downgradeString = 'You are copying configuration data from %s to %s; which is untested and likely to break; proceed?' % (sourceData['systemInfo']['version'], destinationData['systemInfo']['version'])
        if query_yes_no(downgradeString, default="no"):
            print('Proceeding with caution; errors are likely.')
            downgrade = True
        else:
            quit()
    for module in set(sourceData['systemInfo']['provisionedModules']) - set(destinationData['systemInfo']['provisionedModules']):
        moduleMissingString = 'Module from source not on destination: %s - Continue (no to exit)?' % (module)
        if query_yes_no(moduleMissingString, default="no"):
            print('High Possibility of problems due to lack of consistent module provisioning on source and destination')
        else:
            quit()

    # Need to account for missing partitions on destination BIG-IP First - partition will hold string like "Common" (no parantheses)
    for partition in set(sourceData['systemInfo']['partitions']) - set(destinationData['systemInfo']['partitions']):
        partitionMissingString = 'Partition from source not on destination: %s - Create Partition?' % (partition)
        if query_yes_no(partitionMissingString, default="yes"):
            create_partition(partition)
            destinationData['systemInfo']['folders'] = get_folders(args.destinationbigip, args.user, destpasswd)
        else:
            print('Proceeding without creation of partition: %s' % (partition))

    # Creation of a Partition (e.g. Public) creates a top level folder (e.g. /Public) but you can also have folders inside any "partition" folder (e.g. /Common/qa or /Public/qa)
    # Creation of a partition will require regeneration of partition list for machine
    for folder in sorted(set(sourceData['systemInfo']['folders']) - set(destinationData['systemInfo']['folders'])):
        folderMissingString = 'Folder from source not on destination: %s - Create Folder?' % (folder)
        if query_yes_no(folderMissingString, default="yes"):
            create_folder(folder)
        else:
            print('Proceeding without creation of folder: %s' % (folder))

    sourceVirtualsList = sourceData['virtuals']
    for virtual in sourceVirtualsList:
        #print('virtualFullPath: %s' % (virtual['virtualFullPath']))
        if args.allvirtuals or virtual['virtualFullPath'] in args.virtual or virtual['virtualFullPath'].split('/')[-1] in args.virtual:
            #print ('Virtual to Copy: %s' % (virtual['virtualFullPath']))
            if virtual['virtualFullPath'] not in destinationVirtualSet:
                print ('Confirmed Virtual: %s is missing; initiating copy...' % (virtual['virtualFullPath']))
                put_virtual(virtual['virtualFullPath'], virtual['virtualListConfig'])
            else:
                print ('Confirmed Virtual: %s already on destination; skipping virtual' % (virtual['virtualFullPath']))
        else:
            print ('Skipping virtual in source data; virtual not selected: %s' % (virtual['virtualFullPath']))
