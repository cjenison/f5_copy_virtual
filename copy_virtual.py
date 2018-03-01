#!/usr/bin/python

# copy_virtual.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
# Version 1.1 - Significant paring down due to expandSubcollections usage; added support for IP change of virtual as it is copied
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
from collections import OrderedDict


filestorebasepath = '/config/filestore/files_d'

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to move a BIG-IP LTM Virtual Server from one BIG-IP to another', epilog="Note that this utility only validates that destination object [e.g. a pool] exists or not on target system; if target object is found, it doesn't modify it")
parser.add_argument('--sourcebigip', '-s', help='IP or hostname of Source BIG-IP Management or Self IP')
parser.add_argument('--destinationbigip', '-d', help='IP or hostname of Destination BIG-IP Management or Self IP')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
virtual = parser.add_mutually_exclusive_group()
virtual.add_argument('--virtual', '-v', nargs='*', help='Virtual Server(s) to attach to (with full path [e.g. /Common/test])')
virtual.add_argument('--allvirtuals', '-a', help="Copy all virtuals to target system that aren't already found")
mode = parser.add_mutually_exclusive_group()
mode.add_argument('--copy', '-c', help='Copy from source to destination BIG-IP (online for both systems)' action='store_true')
mode.add_argument('--write', '-w', help='Write JSON File Output (provide filename)')
mode.add_argument('--read', '-r', help='Read JSON File Output and push to Destination BIG-IP (provide filename)')
parser.add_argument('--ipchange', '-i', help='Prompt user for new Virtual Server IP (Destination)', action='store_true')
parser.add_argument('--destsuffix', help='Use a suffix for configuration objects on destination [do not re-use existing objects already on destination]')
parser.add_argument('--disableonsource', '-disable', help='Disable Virtual Server on Source BIG-IP if successfully copied to destination')
parser.add_argument('--removeonsource', '-remove', help='Remove Virtual Server on Source BIG-IP if successfully copied to destination')
parser.add_argument('--noprompt', '-n', help='Do not prompt for confirmation of copying operations', action='store_true')

args = parser.parse_args()

contentTypeJsonHeader = {'Content-Type': 'application/json'}

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
    return token

def get_active_software_version(bigip, authHeader):
    bip = requests.session()
    bip.verify = False
    bip.headers.update(authHeader)
    volumes = bip.get('https://%s/mgmt/tm/sys/software/volume' % (bigip)).json()
    for volume in volumes['items']:
        if volume.get('active'):
            if volume['active'] == True:
                activeVersion = volume['version']
    return activeVersion

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
    print('Cert FullPath: %s' % (certFullPath))
    print('Key FullPath: %s' % (keyFullPath))
    sourcessh = paramiko.SSHClient()
    sourcessh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sourcessh.connect(args.sourcebigip, username=args.user, password=passwd, allow_agent=False)
    sourcesftp = sourcessh.open_sftp()
    certFolder = certFullPath.split("/")[1]
    keyFolder = keyFullPath.split("/")[1]
    filestore_basepath = '/config/filestore/files_d/%s_d' % (certFolder)
    print('filestore_basepath: %s' % (filestore_basepath))
    sourcesftp.chdir('%s/certificate_d' % (filestore_basepath))
    sourceCertFiles = sourcesftp.listdir()
    for file in sourceCertFiles:
        if file.replace(":", "/", 2).startswith(certFullPath):
            certFilestoreName = file
    print('certFilestoreName: %s' % (certFilestoreName))
    sourcesftp.chdir('%s/certificate_key_d' % (filestore_basepath))
    sourceKeyFiles = sourcesftp.listdir()
    for file in sourceKeyFiles:
        if file.replace(":", "/", 2).startswith(keyFullPath):
            keyFilestoreName = file
    print('keyFilestoreName: %s' % (certFilestoreName))
    certFileRead = sourcesftp.open('%s/certificate_d/%s' % (filestore_basepath, certFilestoreName), 'r')
    certFile = certFileRead.read()
    print('certFile: %s' % (certFile))
    certFileRead.close()
    keyFileRead = sourcesftp.open('%s/certificate_key_d/%s' % (filestore_basepath, keyFilestoreName), 'r')
    keyFile = keyFileRead.read()
    print('keyFile: %s' % (keyFile))
    keyFileRead.close()
    certWithKey = {'cert': {'fullPath': certFullPath, 'certText': certFile}, 'key': {'fullPath': keyFullPath, 'keyText': keyFile}}
    return certWithKey

def put_cert_and_key(certWithKey):
    print('Cert FullPath: %s' % (certWithKey['cert']['fullPath']))
    print('Key FullPath: %s' % (certWithKey['key']['fullPath']))
    destinationssh = paramiko.SSHClient()
    destinationssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    destinationssh.connect(args.destinationbigip, username=args.user, password=passwd, allow_agent=False)
    destinationsftp = destinationssh.open_sftp()
    destinationsftp.chdir('/tmp/')
    destinationsftp.mkdir('_copy_virtual')
    destinationsftp.chdir('_copy_virtual')
    certFileWrite = destinationsftp.open(certWithKey['cert']['fullPath'].replace("/", ":", 2), 'w')
    certFileWrite.write(certWithKey['cert']['certText'])
    certFileWrite.close()
    keyFileWrite = destinationsftp.open(certWithKey['key']['fullPath'].replace("/", ":", 2), 'w')
    keyFileWrite.write(certWithKey['key']['keyText'])
    keyFileWrite.close()
    cryptoPostPayload = {}
    cryptoPostPayload['command']='install'
    cryptoPostPayload['name']=certWithKey['cert']['fullPath']
    cryptoPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (certWithKey['cert']['fullPath'].replace("/", ":", 2))
    certPost = destinationbip.post('%s/sys/crypto/cert' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(cryptoPostPayload))
    if certPost.status_code == 200:
        print('Successfully Posted Cert: %s to destination BIG-IP' % (certWithKey['cert']['fullPath']))
    else:
        print('Unsuccessful attempt to post cert: %s to destination with JSON: %s' % (certWithKey['cert']['fullPath'], cryptoPostPayload))
        print('Body: %s' % (certPost.content))
    cryptoPostPayload['name']=certWithKey['key']['fullPath']
    cryptoPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (certWithKey['key']['fullPath'].replace("/", ":", 2))
    keyPost = destinationbip.post('%s/sys/crypto/key' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(cryptoPostPayload))
    if keyPost.status_code == 200:
        print('Successfully Posted Key: %s to destination BIG-IP' % (certWithKey['key']['fullPath']))
    else:
        print('Unsuccessful attempt to post key: %s to destination with JSON: %s' % (certWithKey['key']['fullPath'], cryptoPostPayload))
        print('Body: %s' % (keyPost.content))
    destinationsftp.remove(certWithKey['cert']['fullPath'].replace("/", ":", 2))
    destinationsftp.remove(certWithKey['key']['fullPath'].replace("/", ":", 2))
    destinationsftp.rmdir('/tmp/_copy_virtual')

def get_virtual(virtualFullPath):
    virtualDict = sourcebip.get('%s/ltm/virtual/%s?expandSubcollections=true' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    del virtualDict['selfLink']
    if virtualDict.get('pool'):
        virtualConfig.append(get_pool(virtualDict['pool']))
    if virtualDict.get('sourceAddressTranslation').get('pool'):
        virtualConfig.append(get_snatpool(virtualDict['sourceAddressTranslation']['pool']))
    virtualPolicies = virtualDict['policiesReference']
    if virtualPolicies.get('items'):
        for policy in virtualPolicies['items']:
            virtualConfig.append(get_policy(policy['fullPath']))
    #virtualProfiles = sourcebip.get('%s/ltm/virtual/%s/profiles' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    virtualProfiles = virtualDict['profilesReference']
    if virtualProfiles.get('items'):
        for profile in virtualProfiles['items']:
            print('Profile: %s' % (profile['fullPath']))
            virtualConfig.append(get_profile(profile['fullPath']))
    if virtualDict.get('persist'):
        hasPrimaryPersistence = True
        primaryPersistence = virtualDict['persist']
        primaryPersistenceFullPath = '/%s/%s' % (virtualDict['persist'][0]['partition'], virtualDict['persist'][0]['name'])
        virtualConfig.append(get_persistence(primaryPersistenceFullPath))
    if virtualDict.get('fallbackPersistence'):
        virtualConfig.append(get_persistence(virtualDict['fallbackPersistence']))
    if virtualDict.get('rules'):
        for rule in virtualDict['rules']:
            virtualConfig.append(get_rule(rule))
    if args.ipchange:
        changeDestination = 'Source Virtual Server Destination: %s - port: %s mask: %s - Change?' % (virtualDict['destination'].split("/")[2].rsplit(":", 1)[0], virtualDict['destination'].split("/")[2].rsplit(":", 1)[1], virtualDict['mask'])
        if query_yes_no(changeDestination, default="yes"):
            newDestination = obtain_new_vs_destination(virtualDict['destination'].split("/")[2].rsplit(":", 1)[0], virtualDict['destination'].split("/")[2].rsplit(":", 1)[1], virtualDict['mask'])
            destinationPartition = virtualDict['destination'].split("/")[1]
            virtualDict['destination'] = '/%s/%s:%s' % (destinationPartition, newDestination['ip'], newDestination['port'])
            virtualDict['mask'] = newDestination['mask']
    virtualConfig.append(virtualDict)
    return virtualConfig
    #copiedVirtual = destinationbip.post('%s/ltm/virtual/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(virtualDict))
    #if copiedVirtual.status_code == 200:
    #    print('Successfully Copied Virtual: %s' % (virtualFullPath))
    #else:
    #    print('Unsuccessful attempt to copy virtual: %s ; StatusCode: %s' % (virtualFullPath, copiedVirtual.status_code))
    #    print('Body: %s' % (copiedVirtual.content))

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

def get_profile(profileFullPath):
    profileDict = sourcebip.get('%s/ltm/profile/%s/%s' % (sourceurl_base, sourceProfileTypeDict[profileFullPath], profileFullPath.replace("/", "~", 2))).json()
    if sourceProfileTypeDict[profileFullPath] == 'client-ssl':
        print('Profile: %s is client-ssl' % (profileFullPath))
        #if args.getcert:
        #    get_cert_and_key(profileDict['cert'], profileDict['key'])
        if profileDict.get('passphrase'):
            print('Profile: %s uses a key with passphrase protection' % (profileFullPath))
            del profileDict['passphrase']
            # Investigate Chained Certs
            #del profileJson['certKeyChain']
            passphrase = get_passphrase(profileDict['fullPath'])
            profileDict['passphrase'] = passphrase
        else:
            print('Profile: %s does not use passphrase protection' % (profileFullPath))
    return profileDict

def get_rule(ruleFullPath):
    ruleDict = sourcebip.get('%s/ltm/rule/%s' % (sourceurl_base, ruleFullPath.replace("/", "~", 2))).json()
    return ruleDict

def get_persistence(persistenceFullPath):
    persistenceDict = sourcebip.get('%s/ltm/persistence/%s/%s' % (sourceurl_base, sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~", 2))).json()
    return persistenceDict

def get_monitor(monitorFullPath):
    monitorDict = sourcebip.get('%s/ltm/monitor/%s/%s' % (sourceurl_base, sourceMonitorTypeDict[monitorFullPath], monitorFullPath.replace("/", "~", 2))).json()
    return monitorDict

def get_snatpool(snatpoolFullPath):
    snatpoolDict = sourcebip.get('%s/ltm/snatpool/%s' % (sourceurl_base, snatpoolFullPath.replace("/", "~", 2))).json()
    return snatpoolDict

def get_pool(poolFullPath):
    poolDict = sourcebip.get('%s/ltm/pool/%s?expandSubcollections=true' % (sourceurl_base, poolFullPath.replace("/", "~", 2))).json()
    if poolDict.get('monitor'):
        for monitor in poolDict['monitor'].strip().split(' and '):
            virtualConfig.append(get_monitor(monitor))
        for member in poolDict['membersReference']['items']:
            if member['monitor'] != 'default':
                for monitor in member['monitor'].strip().split(' and '):
                    virtualConfig.append(get_monitor(monitor))
    return poolDict

def get_policy(policyFullPath):
    policyDict = sourcebip.get('%s/ltm/policy/%s?expandSubcollections=true' % (sourceurl_base, policyFullPath.replace("/", "~", 2))).json()
    #del policyDict['fullPath']
    ### with 12.1.x+; policies now have "Drafts" or "Published" status (https://support.f5.com/csp/article/K33749970)
    ### need to add code to handle this stuff
    if policyDict.get('status'):
        print('Our source machine is likely 12.1.x or later')
    if policyDict.get('controls'):
        print('Our Source machine may be pre-12.1')
    #policyDict.getpolicyDict['subPath']='Drafts'
    #to get policies published on 12.1 or later, gotta put a a subPath of Drafts in
    virtualDict.append(get_policy_strategy(policyDict['strategy']))
    #copiedPolicy = destinationbip.post('%s/ltm/policy/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(policyJson))
    rulesDict = policyDict['rulesReference']
    #draftFullPath = '/%s/Drafts/%s' % (policyFullPath.split("/")[1], policyFullPath.split("/")[2])
    #print ('draftFullPath: %s' % (draftFullPath))
    #publishCommand = {'command': "publish", 'name': draftFullPath }
    #destinationbip.post('%s/ltm/policy' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(publishCommand))
    print ('Finished getting Policy: %s' % (policyFullPath))
    return policyDict

def get_policy_strategy(policyStrategyFullPath):
    policyStrategyDict = sourcebip.get('%s/ltm/policy-strategy/%s' % (sourceurl_base, policyStrategyFullPath.replace("/", "~", 2))).json()
    return policyStrategyDict

def generate_destination_sets():
    destinationProfileTypes = destinationbip.get('%s/ltm/profile/' % (destinationurl_base)).json()
    for profileType in destinationProfileTypes['items']:
        typeString = profileType['reference']['link'].split("/")[-1].split("?")[0]
        profileTypeCollection = destinationbip.get('%s/ltm/profile/%s' % (destinationurl_base, typeString)).json()
        if profileTypeCollection.get('items'):
            for profile in profileTypeCollection['items']:
                destinationProfileSet.add(profile['fullPath'])

    destinationPools = destinationbip.get('%s/ltm/pool/' % (destinationurl_base)).json()
    if destinationPools.get('items'):
        for pool in destinationPools['items']:
            destinationPoolSet.add(pool['fullPath'])

    destinationMonitorTypes = destinationbip.get('%s/ltm/monitor/' % (destinationurl_base)).json()
    for monitorType in destinationMonitorTypes['items']:
        typeString = monitorType['reference']['link'].split("/")[-1].split("?")[0]
        monitorTypeCollection = destinationbip.get('%s/ltm/monitor/%s' % (destinationurl_base, typeString)).json()
        if monitorTypeCollection.get('items'):
            for monitor in monitorTypeCollection['items']:
                destinationMonitorSet.add(monitor['fullPath'])

    destinationNodes = destinationbip.get('%s/ltm/node/' % (destinationurl_base)).json()
    if destinationNodes.get('items'):
        for node in destinationNodes['items']:
            destinationNodeSet.add(node['fullPath'])

    destinationCerts = destinationbip.get('%s/sys/crypto/cert/' % (destinationurl_base)).json()
    for cert in destinationCerts['items']:
        destinationCertSet.add(cert['fullPath'])

    destinationKeys = destinationbip.get('%s/sys/crypto/key/' % (destinationurl_base)).json()
    for key in destinationKeys['items']:
        destinationKeySet.add(key['fullPath'])

    destinationRules = destinationbip.get('%s/ltm/rule/' % (destinationurl_base)).json()
    for rule in destinationRules['items']:
        destinationRuleSet.add(rule['fullPath'])

    destinationInternalDatagroups = destinationbip.get('%s/ltm/data-group/internal/' % (destinationurl_base)).json()
    if destinationInternalDatagroups.get('items'):
        for datagroup in destinationInternalDatagroups['items']:
            destinationDatagroupSet.add(datagroup['fullPath'])

    destinationExternalDatagroups = destinationbip.get('%s/ltm/data-group/external/' % (destinationurl_base)).json()
    if destinationExternalDatagroups.get('items'):
        for datagroup in destinationExternalDatagroups['items']:
            destinationDatagroupSet.add(datagroup['fullPath'])

    destinationSnatpools = destinationbip.get('%s/ltm/snatpool/' % (destinationurl_base)).json()
    for snatpool in destinationSnatpools['items']:
        destinationSnatpoolSet.add(snatpool['fullPath'])

    destinationPolicies = destinationbip.get('%s/ltm/policy/' % (destinationurl_base)).json()
    for policy in destinationPolicies['items']:
        destinationPolicySet.add(policy['fullPath'])

    destinationPolicyStrategies = destinationbip.get('%s/ltm/policy-strategy/' % (destinationurl_base)).json()
    for policyStrategy in destinationPolicyStrategies['items']:
        destinationPolicyStrategySet.add(policyStrategy['fullPath'])

    destinationPersistenceTypes = destinationbip.get('%s/ltm/persistence/' % (destinationurl_base)).json()
    for persistenceType in destinationPersistenceTypes['items']:
        typeString = persistenceType['reference']['link'].split("/")[-1].split("?")[0]
        persistenceTypeCollection = destinationbip.get('%s/ltm/persistence/%s' % (destinationurl_base, typeString)).json()
        if persistenceTypeCollection.get('items'):
            for persistenceProfile in persistenceTypeCollection['items']:
                destinationPersistenceSet.add(persistenceProfile['fullPath'])


user = args.user
passwd = getpass.getpass("Password for " + user + ":")
requests.packages.urllib3.disable_warnings()

if args.destinationbigip:
    destinationurl_base = ('https://%s/mgmt/tm' % (args.destinationbigip))
    destinationbip = requests.session()
    destinationbip.verify = False
    destinationAuthToken = get_auth_token(args.destinationbigip, args.user, passwd)
    destinationAuthHeader = {'X-F5-Auth-Token': destinationAuthToken}
    destinationbip.headers.update(destinationAuthHeader)
    destinationVersion = get_active_software_version(args.destinationbigip, destinationAuthHeader)
    print('Destination BIG-IP Version: %s' % (destinationVersion))
    destinationPostHeaders = destinationAuthHeader
    destinationPostHeaders.update(contentTypeJsonHeader)
    destinationProfileSet = set()
    destinationMonitorSet = set()
    destinationPoolSet = set()
    destinationNodeSet = set()
    destinationCertSet = set()
    destinationKeySet = set()
    destinationRuleSet = set()
    destinationPolicySet = set()
    destinationPolicyStrategySet = set()
    destinationPersistenceSet = set()
    destinationSnatpoolSet = set()
    destinationDatagroupSet = set()
    # Generate Destination Object Sets (to check for existence)
    generate_destination_sets()
    destinationVirtualSet = set()
    destinationVirtuals = destinationbip.get('%s/ltm/virtual/' % (destinationurl_base)).json()
    if destinationVirtuals.get('items'):
        for virtual in destinationVirtuals['items']:
            destinationVirtualSet.add(virtual['fullPath'])

if args.sourcebigip:
    sourceurl_base = ('https://%s/mgmt/tm' % (args.sourcebigip))
    sourcebip = requests.session()
    sourcebip.verify = False
    sourceAuthToken = get_auth_token(args.sourcebigip, args.user, passwd)
    sourceAuthHeader = {'X-F5-Auth-Token': sourceAuthToken}
    sourcebip.headers.update(sourceAuthHeader)
    sourceVersion = get_active_software_version(args.sourcebigip, sourceAuthHeader)
    print('Source BIG-IP Version: %s' % (sourceVersion))
    sourcePostHeaders = sourceAuthHeader
    sourcePostHeaders.update(contentTypeJsonHeader)


    sourceProfileTypeDict = dict()
    sourceProfiles = sourcebip.get('%s/ltm/profile/' % (sourceurl_base)).json()
    for profile in sourceProfiles['items']:
        typeUrlFragment = profile['reference']['link'].split("/")[-1].split("?")[0]
        profileTypeCollection = sourcebip.get('%s/ltm/profile/%s' % (sourceurl_base, typeUrlFragment)).json()
        if profileTypeCollection.get('items'):
            for profile in profileTypeCollection['items']:
                sourceProfileTypeDict[profile['fullPath']] = typeUrlFragment

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
    for virtual in sourceVirtuals['items']:
        sourceVirtualDict[virtual['name']] = virtual['fullPath']
        sourceVirtualSet.add(virtual['fullPath'])
        if args.allvirtuals:
            if virtual['fullPath'] not in destinationVirtualSet:
                print ('Source Virtual: %s missing from Destination BIG-IP' % (virtual['fullPath']))
                copy_virtual(virtual['fullPath'])

    sourceDatagroupSet = set()
    sourceInternalDatagroups = sourcebip.get('%s/ltm/data-group/internal/' % (sourceurl_base)).json()
    if sourceInternalDatagroups.get('items'):
        for datagroup in sourceInternalDatagroups['items']:
            sourceDatagroupSet.add(datagroup['fullPath'])

    sourceExternalDatagroups = sourcebip.get('%s/ltm/data-group/external/' % (sourceurl_base)).json()
    if sourceExternalDatagroups.get('items'):
        for datagroup in sourceExternalDatagroups['items']:
            sourceDatagroupSet.add(datagroup['fullPath'])

virtualsList = []

if args.virtual is not None:
    for virtual in args.virtual:
        sourceVirtual = dict()
        virtualConfig = []
        if virtual in sourceVirtualSet:
            print ('Virtual(s) to copy: %s' % (virtual))
            #sourceVirtualConfig = get_virtual(virtual)
            sourceVirtual['name'] = virtual
            sourceVirtual['config'] = get_virtual(virtual)
            virtualsList.append(sourceVirtual)
            #if virtual not in destinationVirtualSet:
            #    print('Copying virtual: %s' % (virtual))
            #    copy_virtual(virtual)
            #else:
            #    print('Virtual: %s already present on destination' % (virtual))
        elif virtual in sourceVirtualDict.keys():
            print ('Virtual(s) to copy: %s' % (sourceVirtualDict[virtual]))
            sourceVirtual['name'] = sourceVirtualDict[virtual]
            sourceVirtual['config'] = get_virtual(sourceVirtualDict[virtual])
            virtualsList.append(sourceVirtual)
            #if sourceVirtualDict[virtual] not in destinationVirtualSet:
            #    print ('Virtual(s) to copy: %s' % (sourceVirtualDict[virtual]))
            #    copy_virtual(sourceVirtualDict[virtual])
            #else:
            #    print('Virtual: %s already present on destination' % (virtual))
        else:
            print ('Virtual: %s not found on source BIG-IP' % (virtual))
        print json.dumps(sourceVirtual['config'], indent=4, sort_keys=True)
