#!/usr/bin/python

# copy_virtual.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
# Version 1.1 - Significant paring down due to expandSubcollections usage; added support for IP change of virtual as it is copied
# Version 2.0 - Major changes to support offline operation, using JSON file as storage
#
# Script that attempts to move a virtual (and all supporting configuration) from one BIG-IP to another
# Medium Term To-Do: Try to Handle Missing Cert/Keys by copying with scp
# Medium Term To-Do: Enumerate Datagroups and diff source/destination - determine if irule text shows any string matches for named datagroups in the diff and prompt user for whether datagroups should be copied
# Long Term To-Do: Ensure Target Partition/Folder is in place; optionally allow movement of configuration objects from a source partition to a different target partition (including supporting objects)
# Possible Bugs: if a pool needs to be created on target system and nodes already exist (or there is same IP, differently named), will things break?
# Confirmed Bug: IPv6 incompatible for IP change (due to split(":") line)

import argparse
import sys
import requests
import json
import getpass
import paramiko
from time import sleep

datagroupkeywords = ['equals', 'starts_with', 'ends_with', 'contains']
filestorebasepath = '/config/filestore/files_d'
contentTypeJsonHeader = {'Content-Type': 'application/json'}

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to move a BIG-IP LTM Virtual Server from one BIG-IP to another', epilog="Note that this utility only validates that destination object [e.g. a pool] exists or not on target system; if target object is found, it doesn't modify it")
parser.add_argument('--sourcebigip', '-s', help='IP or hostname of Source BIG-IP Management or Self IP')
parser.add_argument('--destinationbigip', '-d', help='IP or hostname of Destination BIG-IP Management or Self IP')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
virtual = parser.add_mutually_exclusive_group()
virtual.add_argument('--virtual', '-v', nargs='*', help='Virtual server(s) on source to select (example: vs-1 or /Public/vs-1)')
virtual.add_argument('--allvirtuals', '-a', help="Select all virtual servers on source system", action='store_true')
mode = parser.add_mutually_exclusive_group()
mode.add_argument('--copy', '-c', help='Copy from source to destination BIG-IP (online for both systems)', action='store_true')
mode.add_argument('--write', '-w', help='Write JSON File Output (provide filename)')
mode.add_argument('--read', '-r', help='Read JSON File Output and push to Destination BIG-IP (provide filename)')
parser.add_argument('--ipchange', '-i', help='Prompt user for new Virtual Server IP (Destination)', action='store_true')
parser.add_argument('--destsuffix', help='Use a suffix for configuration objects on destination [do not re-use existing objects already on destination]')
parser.add_argument('--disableonsource', '-ds', help='Disable Virtual Server on Source BIG-IP if successfully copied to destination', action='store_true')
parser.add_argument('--disableondestination', '-dd', help='Disable Virtual Server on Destination BIG-IP as it is copied', action='store_true')
parser.add_argument('--nocertandkey', '-nck', help='Do not retrieve or push certs/keys and instead alter reference to default.crt and default.key')
parser.add_argument('--removeonsource', '-remove', help='Remove Virtual Server on Source BIG-IP if successfully copied to destination')
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


def get_system_info(bigip, username, password):
    systemInfo = dict()
    bip = requests.session()
    bip.verify = False
    bip.auth = (username, password)
    #bip.headers.update(authHeader)
    globalSettings = bip.get('https://%s/mgmt/tm/sys/global-settings/' % (bigip)).json()
    hardware = bip.get('https://%s/mgmt/tm/sys/hardware/' % (bigip)).json()
    provision = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
    provisionedModules = set()
    for module in provision['items']:
        if module['level'] != 'none':
            provisionedModules.add(module['name'])
    print ('Provisioned Modules: %s' % (provisionedModules))
    systemInfo['provisionedModules'] = provisionedModules
    systemInfo['baseMac'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['baseMac']['description']
    systemInfo['marketingName'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['marketingName']['description']
    version = bip.get('https://%s/mgmt/tm/sys/version/' % (bigip)).json()
    systemInfo['version'] = version['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description']
    print ('Version: %s' % (systemInfo['version']))
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

def get_cert_and_key(certFullPath, keyFullPath):
    sourcessh = paramiko.SSHClient()
    sourcessh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sourcessh.connect(args.sourcebigip, username=args.user, password=passwd, allow_agent=False)
    sourcesftp = sourcessh.open_sftp()
    certFolder = certFullPath.split("/")[1]
    keyFolder = keyFullPath.split("/")[1]
    filestore_basepath = '/config/filestore/files_d/%s_d' % (certFolder)
    sourcesftp.chdir('%s/certificate_d' % (filestore_basepath))
    sourceCertFiles = sourcesftp.listdir()
    for file in sourceCertFiles:
        if file.replace(":", "/", 2).startswith(certFullPath):
            certFilestoreName = file
    sourcesftp.chdir('%s/certificate_key_d' % (filestore_basepath))
    sourceKeyFiles = sourcesftp.listdir()
    for file in sourceKeyFiles:
        if file.replace(":", "/", 2).startswith(keyFullPath):
            keyFilestoreName = file
    certFileRead = sourcesftp.open('%s/certificate_d/%s' % (filestore_basepath, certFilestoreName), 'r')
    certFile = certFileRead.read()
    certFileRead.close()
    keyFileRead = sourcesftp.open('%s/certificate_key_d/%s' % (filestore_basepath, keyFilestoreName), 'r')
    keyFile = keyFileRead.read()
    keyFileRead.close()
    print('Cert: %s' % (certFullPath))
    print('Key: %s' % (keyFullPath))
    certWithKey = {'cert': {'fullPath': certFullPath, 'certText': certFile}, 'key': {'fullPath': keyFullPath, 'keyText': keyFile}}
    return certWithKey

def put_cert(fullPath, certText):
    destinationssh = paramiko.SSHClient()
    destinationssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    destinationssh.connect(args.destinationbigip, username=args.user, password=passwd, allow_agent=False)
    destinationsftp = destinationssh.open_sftp()
    destinationsftp.chdir('/tmp/')
    destinationsftp.mkdir('_copy_virtual')
    destinationsftp.chdir('_copy_virtual')
    certFileWrite = destinationsftp.open(fullPath.replace("/", ":", 2), 'w')
    certFileWrite.write(certText)
    certFileWrite.close()
    certPostPayload = {}
    certPostPayload['command']='install'
    certPostPayload['name']=fullPath
    certPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (fullPath.replace("/", ":", 2))
    certPost = destinationbip.post('%s/sys/crypto/cert' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(certPostPayload))
    if certPost.status_code == 200:
        print('Successfully Posted Cert: %s to destination BIG-IP' % (fullPath))
        destinationCertSet.add(fullPath)
    else:
        print('Unsuccessful attempt to post cert: %s to destination with JSON: %s' % (fullPath, certPostPayload))
        print('Body: %s' % (certPost.content))
    destinationsftp.remove(fullPath.replace("/", ":", 2))
    destinationsftp.rmdir('/tmp/_copy_virtual')
    destinationsftp.close()

def put_key(fullPath, keyText):
    destinationssh = paramiko.SSHClient()
    destinationssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    destinationssh.connect(args.destinationbigip, username=args.user, password=passwd, allow_agent=False)
    destinationsftp = destinationssh.open_sftp()
    destinationsftp.chdir('/tmp/')
    destinationsftp.mkdir('_copy_virtual')
    destinationsftp.chdir('_copy_virtual')
    keyFileWrite = destinationsftp.open(fullPath.replace("/", ":", 2), 'w')
    keyFileWrite.write(keyText)
    keyFileWrite.close()
    keyPostPayload = {}
    keyPostPayload['command']='install'
    keyPostPayload['name']=fullPath
    keyPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (fullPath.replace("/", ":", 2))
    keyPost = destinationbip.post('%s/sys/crypto/key' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(keyPostPayload))
    if keyPost.status_code == 200:
        print('Successfully Posted Key: %s to destination BIG-IP' % (fullPath))
        destinationKeySet.add(fullPath)
    else:
        print('Unsuccessful attempt to post key: %s to destination with JSON: %s' % (fullPath, keyPostPayload))
        print('Body: %s' % (keyPost.content))
    destinationsftp.remove(fullPath.replace("/", ":", 2))
    destinationsftp.rmdir('/tmp/_copy_virtual')
    destinationsftp.close()

def get_virtual(virtualFullPath):
    virtualDict = sourcebip.get('%s/ltm/virtual/%s?expandSubcollections=true' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    if virtualFullPath in sourceAsmVirtualSet:
        virtualConfig.append(get_asm_policy(sourceAsmPolicyIdNameDict[virtualFullPath]['id'], sourceAsmPolicyIdNameDict[virtualFullPath]['name'], sourceAsmPolicyIdNameDict[virtualFullPath]['fullPath']))
    if virtualDict.get('pool'):
        virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/pool/%s' % (virtualDict['pool'].replace("/", "~", 2))))
    if virtualDict.get('securityLogProfiles'):
        for logProfileReference in virtualDict['securityLogProfilesReference']:
            virtualConfig.append(get_object_by_link(logProfileReference['link']))
    if virtualDict.get('sourceAddressTranslation').get('pool'):
        virtualConfig.append(get_snatpool(virtualDict['sourceAddressTranslation']['pool']))
    virtualPolicies = virtualDict['policiesReference']
    if virtualPolicies.get('items'):
        for policy in virtualPolicies['items']:
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/policy/%s' % (policy['fullPath'].replace("/", "~", 2))))
    #virtualProfiles = sourcebip.get('%s/ltm/virtual/%s/profiles' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    virtualProfiles = virtualDict['profilesReference']
    if virtualProfiles.get('items'):
        index = 0
        badProfiles = []
        # Modify below code to do this profile removal on apply, not on read
        for profile in virtualProfiles['items']:
            if profile['fullPath'] in sourceAsmBotdefenseProfiles:
                print ('Found Reference to automagic ASM bot-defense profile on virtual - removing (it gets regenerated when applied)')
                badProfiles.append(index)
            else:
                if profile.get('nameReference'):
                    virtualConfig.append(get_object_by_link(profile['nameReference']['link']))
                else:
                    virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/profile/%s/%s' % (sourceProfileTypeDict[profile['fullPath']], profile['fullPath'].replace("/", "~", 2))))
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
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/persistence/%s/%s' % (sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~", 2))))
    if virtualDict.get('fallbackPersistence'):
        virtualConfig.append(get_object_by_link(virtualDict['fallbackPersistenceReference']['link']))
    if virtualDict.get('rules'):
        if virtualDict.get('rulesReference'):
            for ruleReference in virtualDict['rulesReference']:
                virtualConfig.append(get_object_by_link(ruleReference['link']))
        else:
            for ruleFullPath in virtualDict['rules']:
                virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/rule/%s' % (ruleFullPath.replace("/", "~", 2))))
    if args.ipchange:
        changeDestination = 'Source Virtual Server Destination: %s - port: %s mask: %s - Change?' % (virtualDict['destination'].split("/")[2].rsplit(":", 1)[0], virtualDict['destination'].split("/")[2].rsplit(":", 1)[1], virtualDict['mask'])
        if query_yes_no(changeDestination, default="yes"):
            newDestination = obtain_new_vs_destination(virtualDict['destination'].split("/")[2].rsplit(":", 1)[0], virtualDict['destination'].split("/")[2].rsplit(":", 1)[1], virtualDict['mask'])
            destinationPartition = virtualDict['destination'].split("/")[1]
            virtualDict['destination'] = '/%s/%s:%s' % (destinationPartition, newDestination['ip'], newDestination['port'])
            virtualDict['mask'] = newDestination['mask']
    virtualConfig.append(virtualDict)
    print ('Virtual: %s' % (virtualDict['fullPath']))
    return virtualConfig

def put_virtual(virtualFullPath, virtualConfigArray):
    print('**Processing Virtual: %s to BIG-IP: %s' % (virtualFullPath, args.destinationbigip))
    for configObject in virtualConfigArray:
        put_json(configObject['fullPath'], configObject)

def put_json(fullPath, configDict):
    #print('kind: %s' % (configDict['kind']))
    if configDict['kind'] == 'tm:asm:custom:asmpolicy':
        put_asm_policy(configDict['policyId'], configDict['policyName'], configDict['xmlPolicy'])
    elif configDict['kind'] == 'tm:security:bot-defense:asm-profile:asm-profilestate':
        print ('Not putting special ASM bot-defense profile: %s' % (configDict['fullPath']))
    else:
        objectUrl = '%s/%s' % (configDict['selfLink'].rsplit("/", 1)[0].replace("localhost", args.destinationbigip, 1), configDict['fullPath'].replace("/", "~", 2))
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
                    print('Downgrading Local Traffic Policies is not supported; removing Policies from Virtual')
                    del configDict['policiesReference']
            elif configDict['kind'] == 'tm:ltm:pool:poolstate':
                for member in configDict['membersReference']['items']:
                    ## Not sure why we need to delete this property, but we do
                    del member['session']
                    del member['state']
                    del member['ephemeral']
            elif configDict['kind'] == 'tm:ltm:snatpool:snatpoolstate':
                if configDict.get('membersReference'):
                    del configDict['membersReference']
            elif configDict['kind'] == 'tm:ltm:policy:policystate':
                if destinationShortVersion >= 12.1:
                    configDict['subPath']='Drafts'
                    configDict['fullPath']='/%s/Drafts/%s' % (configDict['partition'], configDict['name'])
                if downgrade:
                    print('Moving policies to older software revisions is not supported; policy: %s not copied' % (fullPath))
                    return
            elif configDict['kind'] == 'tm:sys:crypto:cert:certstate':
                if fullPath not in destinationCertSet and not args.nocertandkey:
                    if configDict.get('certText'):
                        put_cert(configDict['fullPath'], configDict['certText'])
            elif configDict['kind'] == 'tm:sys:crypto:key:keystate':
                if fullPath not in destinationKeySet and not args.nocertandkey:
                    if configDict.get('keyText'):
                        put_key(configDict['fullPath'], configDict['keyText'])
            elif configDict['kind'] == 'tm:ltm:profile:client-ssl:client-sslstate':
                ### FIX BELOW TO Handle CertkeyChain properly
                if configDict.get('certKeyChain'):
                    del configDict['certKeyChain']
                if configDict['cert'] not in destinationCertSet or configDict['key'] not in destinationKeySet:
                    print('cert: %s and/or key: %s missing on destination - altering cert/key references to default.crt/default.key')
                    configDict['cert'] = '/Common/default.crt'
                    configDict['key'] = '/Common/default.crt'
                else:
                    if configDict.get('passphrase'):
                        print('Source client-ssl profile: %s contains encrypted passphrase; need to re-obtain passphrase')
                        print('**Note: passphrases are encrypted on BIG-IP using Secure Vault technology')
                        print('**Note: passphrase will be submitted via iControl REST, but will be immediately encrypted on BIG-IP')
                        configDict['passphrase'] = get_passphrase(configDict['fullPath'])
            print ('Posting to: %s' % (postUrl))
            destinationObjectPost = destinationbip.post(postUrl, headers=destinationPostHeaders, data=json.dumps(configDict))
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

def get_cert(certFullPath):
    certDict = sourcebip.get('%s/sys/crypto/cert/%s' % (sourceurl_base, certFullPath.replace("/", "~", 2))).json()
    return certDict

def get_key(keyFullPath):
    keyDict = sourcebip.get('%s/sys/crypto/key/%s' % (sourceurl_base, keyFullPath.replace("/", "~", 2))).json()
    return keyDict

def get_object_by_link(link):
    print ('link to get: %s' % (link))
    if '/ltm/pool/' in link or '/ltm/policy/' in link:
        objectDict = sourcebip.get('%s?expandSubcollections=true' % (link.replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    else:
        objectDict = sourcebip.get('%s' % (link.replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    print ('link: %s' % (link.replace("localhost", args.sourcebigip, 1).split("?")[0]))
    if objectDict['kind'] == 'tm:ltm:profile:client-ssl:client-sslstate':
        if not args.nocertandkey:
            cert = get_cert(objectDict['cert'])
            key = get_key(objectDict['key'])
            certAndKey = get_cert_and_key(objectDict['cert'], objectDict['key'])
            cert['certText']=certAndKey['cert']['certText']
            key['keyText']=certAndKey['key']['keyText']
            virtualConfig.append(cert)
            virtualConfig.append(key)
        else:
            print('May need to adjust profile reference to default.crt and default.key')
            #alter references in profile to default.crt and default.key
    elif objectDict['kind'] == 'tm:ltm:policy:policystate':
        virtualConfig.append(get_policy_strategy(objectDict['strategy']))
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
            virtualConfig.append(get_object_by_link('https://localhost/mgmt/tm/ltm/data-group/%s/%s' % (sourceDatagroupTypeDict[matchedDatagroup], matchedDatagroup.replace("/", "~", 2))))
            #virtualConfig.append(get_datagroup(matchedDatagroup))
        ifileHits = set()
        for ifile in sourceIfileSet:
            if ifile.split("/")[1] == 'Common':
                ifilename = ifile.split("/")[2]
                searchString = 'ifile get \"%s\"' % (ifilename)
                if searchString in objectDict['apiAnonymous']:
                    ifileHits.add(ifile)
                    print ('Detected a possible iFile dependency in iRule: %s for ifile: %s [Please resolve this manually]' % (objectDict['fullPath'], ifile))
        print ('ifileHits: %s' % (ifileHits))

    elif objectDict['kind'] == "tm:ltm:pool:poolstate":
        if objectDict.get('monitor'):
            for monitor in objectDict['monitor'].strip().split(' and '):
                virtualConfig.append(get_monitor(monitor))
        for member in objectDict['membersReference']['items']:
            if member['monitor'] != 'default':
                for monitor in member['monitor'].strip().split(' and '):
                    virtualConfig.append(get_monitor(monitor))

    print('source: %s kind: %s' % (objectDict['fullPath'], objectDict['kind']))
    return objectDict

def get_object(profileReference):
    objectDict = sourcebip.get('%s' % (profileReference['nameReference']['link'].replace("localhost", args.sourcebigip, 1).split("?")[0])).json()
    print('Profile: %s' % (objectDict['fullPath']))
    return objectDict

#def get_datagroup(datagroupFullPath):
#    datagroupDict = sourcebip.get('%s/ltm/data-group/%s/%s' % (sourceurl_base, sourceDatagroupTypeDict[datagroupFullPath], datagroupFullPath.replace("/", "~", 2))).json()
#    return datagroupDict

#def get_persistence(persistenceFullPath):
#    persistenceDict = sourcebip.get('%s/ltm/persistence/%s/%s' % (sourceurl_base, sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~", 2))).json()
#    return persistenceDict

def get_monitor(monitorFullPath):
    monitorDict = sourcebip.get('%s/ltm/monitor/%s/%s' % (sourceurl_base, sourceMonitorTypeDict[monitorFullPath], monitorFullPath.replace("/", "~", 2))).json()
    return monitorDict

def get_snatpool(snatpoolFullPath):
    snatpoolDict = sourcebip.get('%s/ltm/snatpool/%s' % (sourceurl_base, snatpoolFullPath.replace("/", "~", 2))).json()
    return snatpoolDict

#def get_policy(policyFullPath):
#    policyDict = sourcebip.get('%s/ltm/policy/%s?expandSubcollections=true' % (sourceurl_base, policyFullPath.replace("/", "~", 2))).json()
#    virtualConfig.append(get_policy_strategy(policyDict['strategy']))
#    return policyDict

def get_policy_strategy(policyStrategyFullPath):
    policyStrategyDict = sourcebip.get('%s/ltm/policy-strategy/%s' % (sourceurl_base, policyStrategyFullPath.replace("/", "~", 2))).json()
    return policyStrategyDict

def generate_dest_asm_policy_set():
    destinationAsmPolicies = destinationbip.get('%s/asm/policies/' % (destinationurl_base)).json()
    for policy in destinationAsmPolicies['items']:
        print('policy name: %s' % (policy['name']))

def put_asm_policy(policyId, policyName, xmlPolicy):
    #policyUpload = destinationbip.post('https://%s/mgmt/tm/asm/file-transfer/uploads/%s.xml' % (args.destinationbigip, policyName), headers=fileUploadHeader, data=xmlPolicy )
    #print ('policyUpload Response: %s' % (policyUpload.content))
    #print ('policyUploadResponse: %s' % (policyUpload.content))
    ### Add a check to see that ASM is provisioned
    if 'asm' in destinationData['provisionedModules']:
        print ('we have ASM')
        policyImportPayload = {'file': xmlPolicy, 'status': 'NEW' }
        importPolicyTask = destinationbip.post('https://%s/mgmt/tm/asm/tasks/import-policy' % (args.destinationbigip), headers=destinationPostHeaders, data=json.dumps(policyImportPayload)).json()
        taskId = importPolicyTask['id']
        print ('upload taskId: %s' % (taskId))
        taskDone = False
        while not taskDone:
            task = destinationbip.get('https://%s/mgmt/tm/asm/tasks/import-policy/%s' % (args.destinationbigip, taskId)).json()
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

user = args.user
passwd = getpass.getpass('Enter Password for %s:' % (user))

requests.packages.urllib3.disable_warnings()


if args.destinationbigip and (args.copy or args.read):
    destinationurl_base = ('https://%s/mgmt/tm' % (args.destinationbigip))
    destinationbip = requests.session()
    destinationbip.verify = False
    destpasswd = getConfirmedPassword(args.destinationbigip, user, passwd)
    destinationSystemInfo = get_system_info(args.destinationbigip, args.user, destpasswd)
    destinationData = get_system_info(args.destinationbigip, args.user, destpasswd)
    destinationVersion = destinationSystemInfo['version']
    destinationShortVersion = float('%s.%s' % (destinationSystemInfo['version'].split(".")[0], destinationSystemInfo['version'].split(".")[1]))
    destinationAuthHeader = {}
    if destinationShortVersion >= 11.6:
        destinationAuthToken = get_auth_token(args.destinationbigip, args.user, destpasswd)
        destinationAuthHeader['X-F5-Auth-Token']=destinationAuthToken
        destinationbip.headers.update(destinationAuthHeader)
    else:
        destinationbip.auth = (args.user, destpasswd)
    print('Destination BIG-IP Hostname: %s' % (destinationSystemInfo['hostname']))
    print('Destination BIG-IP Software: %s' % (destinationSystemInfo['version']))
    destinationPostHeaders = destinationAuthHeader
    destinationPostHeaders.update(contentTypeJsonHeader)
    destinationCertSet = set()
    destinationKeySet = set()
    destinationVirtualSet = set()
    destinationVirtuals = destinationbip.get('%s/ltm/virtual/' % (destinationurl_base)).json()
    if destinationVirtuals.get('items'):
        for virtual in destinationVirtuals['items']:
            destinationVirtualSet.add(virtual['fullPath'])
    destinationCerts = destinationbip.get('%s/sys/crypto/cert/' % (destinationurl_base)).json()
    for cert in destinationCerts['items']:
        destinationCertSet.add(cert['fullPath'])
    destinationKeys = destinationbip.get('%s/sys/crypto/key/' % (destinationurl_base)).json()
    for key in destinationKeys['items']:
        destinationKeySet.add(key['fullPath'])


if args.sourcebigip and (args.copy or args.write):
    sourceurl_base = ('https://%s/mgmt/tm' % (args.sourcebigip))
    sourcebip = requests.session()
    sourcebip.verify = False
    sourcepasswd = getConfirmedPassword(args.sourcebigip, user, passwd)
    #sourceSystemInfo = get_system_info(args.sourcebigip, args.user, sourcepasswd)
    sourceData = get_system_info(args.sourcebigip, args.user, sourcepasswd)
    sourceVersion = sourceData['version']
    sourceShortVersion = float('%s.%s' % (sourceData['version'].split(".")[0], sourceData['version'].split(".")[1]))
    sourceAuthHeader = {}
    if sourceShortVersion >= 11.6:
        sourceAuthToken = get_auth_token(args.sourcebigip, args.user, sourcepasswd)
        sourceAuthHeader['X-F5-Auth-Token']=sourceAuthToken
        sourcebip.headers.update(sourceAuthHeader)
    else:
        sourcebip.auth = (args.user, sourcepasswd)
    print('Source BIG-IP Hostname: %s' % (sourceData['hostname']))
    print('Source BIG-IP Software: %s' % (sourceData['version']))
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
    print('sourceIfileSet: %s' % (sourceIfileSet))

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

if args.copy or args.write:
    sourceData['kind'] = 'f5:unofficial:virtual:copy:utility:data'
    if args.virtual is not None:
        virtuals = args.virtual
    elif args.allvirtuals:
        virtuals = sourceVirtualSet
    for virtual in virtuals:
        sourceVirtual = dict()
        virtualConfig = []
        if virtual in sourceVirtualSet:
            #print ('Virtual(s) to copy: %s' % (virtual))
            sourceVirtual['virtualFullPath'] = virtual
            sourceVirtual['virtualListConfig'] = get_virtual(virtual)
            virtualsList.append(sourceVirtual)
        elif virtual in sourceVirtualDict.keys():
            print ('Virtual(s) to copy: %s' % (sourceVirtualDict[virtual]))
            sourceVirtual['virtualFullPath'] = sourceVirtualDict[virtual]
            sourceVirtual['virtualListConfig'] = get_virtual(sourceVirtualDict[virtual])
            virtualsList.append(sourceVirtual)
        else:
            print ('Virtual: %s not found on source BIG-IP' % (virtual))
    sourceData['virtuals'] = virtualsList
    if args.write:
        with open(args.write, 'w') as fileOut:
            json.dump(sourceData, fileOut, indent=4, sort_keys=True)



if args.copy or args.read:
    if args.read:
        print('Reading Virtual Config Data from file: %s' % (args.read))
        with open(args.read, 'r') as fileIn:
            sourceData = json.load(fileIn)
    elif args.copy:
        print ('Copy Mode: beginning copy of virtuals to destination')
    sourceShortVersion = float('%s.%s' % (sourceData['version'].split(".")[0], sourceData['version'].split(".")[1]))
    destinationShortVersion = float('%s.%s' % (destinationSystemInfo['version'].split(".")[0], destinationSystemInfo['version'].split(".")[1]))
    if sourceShortVersion > destinationShortVersion:
        print ('Houston We Have a Problem')
        downgradeString = 'You are copying configuration data from %s to %s; which is untested and likely to break; proceed?' % (sourceData['version'], destinationSystemInfo['version'])
        if query_yes_no(downgradeString, default="no"):
            print('Proceeding with caution; errors are likely.')
            downgrade = True
        else:
            quit()
    virtualsList = sourceData['virtuals']
    for virtual in virtualsList:
        print('virtualFullPath: %s' % (virtual['virtualFullPath']))
        if args.allvirtuals or virtual['virtualFullPath'] in args.virtual or virtual['virtualFullPath'].split('/')[-1] in args.virtual:
            print ('We will copy this one: %s' % (virtual['virtualFullPath']))
            put_virtual(virtual['virtualFullPath'], virtual['virtualListConfig'])
        else:
            print ('We will skip this one: %s' % (virtual['virtualFullPath']))
