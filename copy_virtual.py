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


filestorebasepath = '/config/filestore/files_d'

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to move a BIG-IP LTM Virtual Server from one BIG-IP to another', epilog="Note that this utility only validates that destination object [e.g. a pool] exists or not on target system; if target object is found, it doesn't modify it")
parser.add_argument('--sourcebigip', '-s', help='IP or hostname of Source BIG-IP Management or Self IP', required=True)
parser.add_argument('--destinationbigip', '-d', help='IP or hostname of Destination BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
virtual = parser.add_mutually_exclusive_group()
virtual.add_argument('--virtual', '-v', nargs='*', help='Virtual Server(s) to attach to (with full path [e.g. /Common/test])')
virtual.add_argument('--allvirtuals', '-a', help="Copy all virtuals to target system that aren't already found")
parser.add_argument('--ipchange', '-i', help='Prompt user for new Virtual Server IP (Destination)', action='store_true')
parser.add_argument('--destsuffix', help='Use a suffix for configuration objects on destination [do not re-use existing objects already on destination]')
parser.add_argument('--offlinewrite', help='Store Configuration JSON to a file (provide filename)')
parser.add_argument('--offlineread', help='Read Configuration JSON from a file (provide filename)')
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

def copy_cert_and_key(certFullPath, keyFullPath):
    print('Cert FullPath: %s' % (certFullPath))
    print('Key FullPath: %s' % (keyFullPath))
    sourcessh = paramiko.SSHClient()
    destinationssh = paramiko.SSHClient()
    sourcessh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    destinationssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sourcessh.connect(args.sourcebigip, username=args.user, password=passwd, allow_agent=False)
    destinationssh.connect(args.destinationbigip, username=args.user, password=passwd, allow_agent=False)
    sourcesftp = sourcessh.open_sftp()
    destinationsftp = destinationssh.open_sftp()
    destinationsftp.chdir('/tmp/')
    destinationsftp.mkdir('_copy_virtual')
    destinationsftp.chdir('_copy_virtual')
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
    certFileWrite = destinationsftp.open(certFullPath.replace("/", ":", 2), 'w')
    certFileWrite.write(certFile)
    certFileWrite.close()
    keyFileWrite = destinationsftp.open(keyFullPath.replace("/", ":", 2), 'w')
    keyFileWrite.write(keyFile)
    keyFileWrite.close()
    cryptoPostPayload = {}
    cryptoPostPayload['command']='install'
    cryptoPostPayload['name']=certFullPath
    cryptoPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (certFullPath.replace("/", ":", 2))
    certPost = destinationbip.post('%s/sys/crypto/cert' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(cryptoPostPayload))
    if certPost.status_code == 200:
        print('Successfully Posted Cert: %s to destination BIG-IP' % (certFullPath))
    else:
        print('Unsuccessful attempt to post cert: %s to destination with JSON: %s' % (certFullPath, cryptoPostPayload))
        print('Body: %s' % (certPost.content))
    cryptoPostPayload['name']=keyFullPath
    cryptoPostPayload['from-local-file']='/tmp/_copy_virtual/%s' % (keyFullPath.replace("/", ":", 2))
    keyPost = destinationbip.post('%s/sys/crypto/key' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(cryptoPostPayload))
    if keyPost.status_code == 200:
        print('Successfully Posted Key: %s to destination BIG-IP' % (keyFullPath))
    else:
        print('Unsuccessful attempt to post key: %s to destination with JSON: %s' % (keyFullPath, cryptoPostPayload))
        print('Body: %s' % (keyPost.content))
    destinationsftp.remove(certFullPath.replace("/", ":", 2))
    destinationsftp.remove(keyFullPath.replace("/", ":", 2))
    destinationsftp.rmdir('/tmp/_copy_virtual')

def copy_virtual(virtualFullPath):
    virtualJson = sourcebip.get('%s/ltm/virtual/%s?expandSubcollections=true' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    del virtualJson['selfLink']
    if virtualJson.get('pool'):
        if virtualJson['pool'] not in destinationPoolSet:
            copy_pool(virtualJson['pool'])
        else:
            print('Pool: %s - Already on destination and left in place' % (virtualJson['pool']))
    if virtualJson.get('sourceAddressTranslation').get('pool'):
        if virtualJson['sourceAddressTranslation']['pool'] not in destinationSnatpoolSet:
            copy_snatpool(virtualJson['sourceAddressTranslation']['pool'])
        else:
            print('Snatpool: %s - Already on destination' % (virtualJson['sourceAddressTranslation']['pool']))
    virtualPolicies = virtualJson['policiesReference']
    if virtualPolicies.get('items'):
        for policy in virtualPolicies['items']:
            if policy['fullPath'] not in destinationPolicySet:
                copy_policy(policy['fullPath'])
            else:
                print('Policy: %s - already on destination and left in place' % (policy['fullPath']))
    #virtualProfiles = sourcebip.get('%s/ltm/virtual/%s/profiles' % (sourceurl_base, virtualFullPath.replace("/", "~", 2))).json()
    virtualProfiles = virtualJson['profilesReference']
    if virtualProfiles.get('items'):
        for profile in virtualProfiles['items']:
            print('Profile: %s' % (profile['fullPath']))
            if profile['fullPath'] not in destinationProfileSet:
                print('Missing Profile on Destination: %s' % (profile['fullPath']))
                copy_profile(profile['fullPath'])
            else:
                print('Profile: %s - already on destination and left in place' % (profile['fullPath']))
    if virtualJson.get('persist'):
        hasPrimaryPersistence = True
        primaryPersistence = virtualJson['persist']
        primaryPersistenceFullPath = '/%s/%s' % (virtualJson['persist'][0]['partition'], virtualJson['persist'][0]['name'])
        if primaryPersistenceFullPath not in destinationPersistenceSet:
            print('Primary Persistence Profile: %s missing on destination' % (primaryPersistenceFullPath))
            copy_persistence(primaryPersistenceFullPath)
        else:
            print('Primary Persistence Profile: %s already on destination' % (primaryPersistenceFullPath))
    if virtualJson.get('fallbackPersistence'):
        if virtualJson['fallbackPersistence'] not in destinationPersistenceSet:
            print('Fallback Persistence Profile: %s missing on destination' % (virtualJson['fallbackPersistence']))
            copy_persistence(virtualJson['fallbackPersistence'])
        else:
            print('Fallback Persistence Profile: %s already on destination' % (virtualJson['fallbackPersistence']))
    if virtualJson.get('rules'):
        for rule in virtualJson['rules']:
            if rule not in destinationRuleSet:
                print ('Rule: %s missing on destination' % (rule))
                copy_rule(rule)
            else:
                print('Rule: %s - already on destination and left in place' % (rule))
    if args.ipchange:
        #### IPv6 Problem in the Split(":") usage
        changeDestination = 'Source Virtual Server Destination: %s - port: %s mask: %s - Change?' % (virtualJson['destination'].split("/")[2].rsplit(":", 1)[0], virtualJson['destination'].split("/")[2].rsplit(":", 1)[1], virtualJson['mask'])
        if query_yes_no(changeDestination, default="yes"):
            newDestination = obtain_new_vs_destination(virtualJson['destination'].split("/")[2].rsplit(":", 1)[0], virtualJson['destination'].split("/")[2].rsplit(":", 1)[1], virtualJson['mask'])
            destinationPartition = virtualJson['destination'].split("/")[1]
            virtualJson['destination'] = '/%s/%s:%s' % (destinationPartition, newDestination['ip'], newDestination['port'])
            virtualJson['mask'] = newDestination['mask']
    copiedVirtual = destinationbip.post('%s/ltm/virtual/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(virtualJson))
    if copiedVirtual.status_code == 200:
        print('Successfully Copied Virtual: %s' % (virtualFullPath))
    else:
        print('Unsuccessful attempt to copy virtual: %s ; StatusCode: %s' % (virtualFullPath, copiedVirtual.status_code))
        print('Body: %s' % (copiedVirtual.content))

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

def copy_profile(profileFullPath):
    profileJson = sourcebip.get('%s/ltm/profile/%s/%s' % (sourceurl_base, sourceProfileTypeDict[profileFullPath], profileFullPath.replace("/", "~", 2))).json()
    if sourceProfileTypeDict[profileFullPath] == 'client-ssl':
        print('Profile: %s is client-ssl' % (profileFullPath))
        if profileJson['cert'] not in destinationCertSet or profileJson['key'] not in destinationKeySet:
            copy_cert_and_key(profileJson['cert'], profileJson['key'])
        if profileJson.get('passphrase'):
            print('Profile: %s uses a key with passphrase protection' % (profileFullPath))
            del profileJson['passphrase']
            del profileJson['certKeyChain']
            passphrase = get_passphrase(profileJson['fullPath'])
            profileJson['passphrase'] = passphrase
        else:
            print('Profile: %s does not use passphrase protection' % (profileFullPath))
    del profileJson['selfLink']
    copiedProfile = destinationbip.post('%s/ltm/profile/%s' % (destinationurl_base, sourceProfileTypeDict[profileFullPath]), headers=destinationPostHeaders, data=json.dumps(profileJson))
    if copiedProfile.status_code == 200:
        print ('Successfully Copied %s Profile: %s' % (sourceProfileTypeDict[profileFullPath], profileFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy %s profile: %s ; StatusCode: %s' % (sourceProfileTypeDict[profileFullPath], profileFullPath, copiedProfile.status_code))
        print ('Body: %s' % (copiedProfile.content))

def copy_rule(ruleFullPath):
    ruleJson = sourcebip.get('%s/ltm/rule/%s' % (sourceurl_base, ruleFullPath.replace("/", "~", 2))).json()
    #if ruleJson.get('selfLink'):
    del ruleJson['selfLink']
    copiedRule = destinationbip.post('%s/ltm/rule' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(ruleJson))
    if copiedRule.status_code == 200:
        print ('Successfully Copied Rule: %s' % (ruleFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy rule: %s ; StatusCode: %s' % (ruleFullPath, copiedRule.status_code))
        print ('Body: %s' % (copiedRule.content))

def copy_persistence(persistenceFullPath):
    persistenceJson = sourcebip.get('%s/ltm/persistence/%s/%s' % (sourceurl_base, sourcePersistenceTypeDict[persistenceFullPath], persistenceFullPath.replace("/", "~", 2))).json()
    del persistenceJson['selfLink']
    copiedPersistence = destinationbip.post('%s/ltm/persistence/%s' % (destinationurl_base, sourcePersistenceTypeDict[persistenceFullPath]), headers=destinationPostHeaders, data=json.dumps(persistenceJson))
    if copiedPersistence.status_code == 200:
        print ('Successfully Copied Persistence Profile: %s' % (persistenceFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy persistence profile: %s ; StatusCode: %s' % (persistenceFullPath, copiedPersistence.status_code))
        print ('Body: %s' % (copiedPersistence.content))

def copy_monitor(monitorFullPath):
    monitorJson = sourcebip.get('%s/ltm/monitor/%s/%s' % (sourceurl_base, sourceMonitorTypeDict[monitorFullPath], monitorFullPath.replace("/", "~", 2))).json()
    del monitorJson['selfLink']
    copiedMonitor = destinationbip.post('%s/ltm/monitor/%s' % (destinationurl_base, sourceMonitorTypeDict[monitorFullPath]), headers=destinationPostHeaders, data=json.dumps(monitorJson))
    if copiedMonitor.status_code == 200:
        print ('Successfully Copied Monitor: %s' % (monitorFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy monitor: %s ; StatusCode: %s' % (monitorFullPath, copiedMonitor.status_code))
        print ('Body: %s' % (copiedMonitor.content))

def copy_snatpool(snatpoolFullPath):
    snatpoolJson = sourcebip.get('%s/ltm/snatpool/%s' % (sourceurl_base, snatpoolFullPath.replace("/", "~", 2))).json()
    del snatpoolJson['selfLink']
    copiedSnatpool = destinationbip.post('%s/ltm/snatpool/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(snatpoolJson))
    if copiedSnatpool.status_code == 200:
        print ('Successfully Copied Snatpool: %s' % (snatpoolFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy snatpool: %s ; StatusCode: %s' % (snatpoolFullPath, copiedSnatpool.status_code))
        print ('Body: %s' % (copiedSnatpool.content))

def copy_pool(poolFullPath):
    poolJson = sourcebip.get('%s/ltm/pool/%s' % (sourceurl_base, poolFullPath.replace("/", "~", 2))).json()
    del poolJson['selfLink']
    if poolJson.get('monitor'):
        for monitor in poolJson['monitor'].strip().split(" and "):
            if monitor not in destinationMonitorSet:
                copy_monitor(monitor)
    copiedPool = destinationbip.post('%s/ltm/pool/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(poolJson))
    if copiedPool.status_code == 200:
        print ('Successfully Copied Pool: %s' % (poolFullPath))
        # Now copy members
        membersJson = sourcebip.get('%s/ltm/pool/%s/members' % (sourceurl_base, poolFullPath.replace("/", "~", 2))).json()
        for member in membersJson['items']:
            del member['state']
            del member['selfLink']
            del member['session']
            if member['monitor'] != 'default':
                print('Member: %s has monitor: %s' % (member['name'], member['monitor']))
		for monitor in member['monitor'].strip().split(" and "):
                    if monitor not in destinationMonitorSet:
                        copy_monitor(monitor)
                        generate_destination_sets()
            else:
                print('Member: %s has default monitor' % (member['name']))
            copiedMember = destinationbip.post('%s/ltm/pool/%s/members/' % (destinationurl_base, poolFullPath.replace("/", "~", 2)), data=json.dumps(member))
            if copiedMember.status_code == 200:
                print ('Successfully Copied Member: %s for Pool: %s' % (member['name'], poolFullPath))
            else:
                print ('Unsuccessful attempt to copy member for pool: %s ; StatusCode: %s' % (poolFullPath, copiedMember.status_code))
                print ('Body: %s' % (copiedMember.content))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy pool: %s ; StatusCode: %s' % (poolFullPath, copiedPool.status_code))
        print ('Body: %s' % (copiedPool.content))

def copy_policy(policyFullPath):
    policyJson = sourcebip.get('%s/ltm/policy/%s' % (sourceurl_base, policyFullPath.replace("/", "~", 2))).json()
    del policyJson['selfLink']
    del policyJson['fullPath']
    del policyJson['rulesReference']
    ### with 12.1.x+; policies now have "Drafts" or "Published" status (https://support.f5.com/csp/article/K33749970)
    ### need to add code to handle this stuff
    del policyJson['status']
    policyJson['subPath']='Drafts'
    if policyJson['strategy'] not in destinationPolicyStrategySet:
        copy_policy_strategy(policyJson['strategy'])
    copiedPolicy = destinationbip.post('%s/ltm/policy/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(policyJson))
    if copiedPolicy.status_code == 200:
        print ('Successfully Copied Policy: %s' % (policyFullPath))
    else:
        print ('Unsuccessful attempt to copy policy: %s ; StatusCode: %s' % (policyFullPath, copiedPolicy.status_code))
        print ('Body: %s' % (copiedPolicy.content))
    rulesJson = sourcebip.get('%s/ltm/policy/%s/rules?expandSubcollections=true' % (sourceurl_base, policyFullPath.replace("/", "~", 2))).json()
    draftFullPath = '/%s/Drafts/%s' % (policyFullPath.split("/")[1], policyFullPath.split("/")[2])
    print ('draftFullPath: %s' % (draftFullPath))
    if rulesJson.get('items'):
        for rule in rulesJson['items']:
            print('rule: %s' % (rule['name']))
            copiedRule = destinationbip.post('%s/ltm/policy/%s/rules/' % (destinationurl_base, draftFullPath.replace("/", "~", 3)), headers=destinationPostHeaders, data=json.dumps(rule))
            if copiedRule.status_code == 200:
                print('Successfully Copied Rule: %s' % (rule['fullPath']))
            else:
                print ('Unsuccessful attempt to copy rule: %s ; StatusCode: %s' % (rule['name'], copiedRule.status_code))
                print ('Body: %s' % (copiedRule.content))
    publishCommand = {'command': "publish", 'name': draftFullPath }
    destinationbip.post('%s/ltm/policy' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(publishCommand))
    print ('Finished copying Policy: %s' % (policyFullPath))
    generate_destination_sets()

def copy_policy_strategy(policyStrategyFullPath):
    policyStrategyJson = sourcebip.get('%s/ltm/policy-strategy/%s' % (sourceurl_base, policyStrategyFullPath.replace("/", "~", 2))).json()
    del policyStrategyJson['selfLink']
    copiedPolicyStrategy = destinationbip.post('%s/ltm/policy-strategy/' % (destinationurl_base), headers=destinationPostHeaders, data=json.dumps(policyStrategyJson))
    if copiedPolicyStrategy.status_code == 200:
        print ('Successfully Copied Policy-Strategy: %s' % (policyStrategyFullPath))
        generate_destination_sets()
    else:
        print ('Unsuccessful attempt to copy policy strategy: %s ; StatusCode: %s' % (policyStrategyFullPath, copiedPolicyStrategy.status_code))
        print ('Body: %s' % (copiedPolicyStrategy.content))

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

sourceurl_base = ('https://%s/mgmt/tm' % (args.sourcebigip))
destinationurl_base = ('https://%s/mgmt/tm' % (args.destinationbigip))
user = args.user
passwd = getpass.getpass("Password for " + user + ":")
sourcebip = requests.session()
sourcebip.verify = False
destinationbip = requests.session()
destinationbip.verify = False
requests.packages.urllib3.disable_warnings()
sourceAuthToken = get_auth_token(args.sourcebigip, args.user, passwd)
sourceAuthHeader = {'X-F5-Auth-Token': sourceAuthToken}
sourcebip.headers.update(sourceAuthHeader)
destinationAuthToken = get_auth_token(args.destinationbigip, args.user, passwd)
destinationAuthHeader = {'X-F5-Auth-Token': destinationAuthToken}
destinationbip.headers.update(destinationAuthHeader)
sourceVersion = get_active_software_version(args.sourcebigip, sourceAuthHeader)
print('Source BIG-IP Version: %s' % (sourceVersion))
destinationVersion = get_active_software_version(args.destinationbigip, destinationAuthHeader)
print('Destination BIG-IP Version: %s' % (destinationVersion))

# combine two Python Dicts (our auth token and the Content-type json header) in preparation for doing POSTs
sourcePostHeaders = sourceAuthHeader
sourcePostHeaders.update(contentTypeJsonHeader)
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
generate_destination_sets()

destinationVirtualSet = set()

destinationVirtuals = destinationbip.get('%s/ltm/virtual/' % (destinationurl_base)).json()
if destinationVirtuals.get('items'):
    for virtual in destinationVirtuals['items']:
        destinationVirtualSet.add(virtual['fullPath'])

#print('destinationVirtualSet: %s' % (destinationVirtualSet))

missingDatagroupSet = set()
sourceInternalDatagroups = sourcebip.get('%s/ltm/data-group/internal/' % (sourceurl_base)).json()
if sourceInternalDatagroups.get('items'):
    for datagroup in sourceInternalDatagroups['items']:
        if datagroup['fullPath'] not in destinationDatagroupSet:
            missingDatagroupSet.add(datagroup['fullPath'])

sourceExternalDatagroups = sourcebip.get('%s/ltm/data-group/external/' % (sourceurl_base)).json()
if sourceExternalDatagroups.get('items'):
    for datagroup in sourceExternalDatagroups['items']:
        if datagroup['fullPath'] not in destinationDatagroupSet:
            missingDatagroupSet.add(datagroup['fullPath'])

print ('missingDatagroupSet: %s' % datagroup['fullPath'])

sourceProfileTypeDict = dict()
sourceProfiles = sourcebip.get('%s/ltm/profile/' % (sourceurl_base)).json()
for profile in sourceProfiles['items']:
    typeUrlFragment = profile['reference']['link'].split("/")[-1].split("?")[0]
    profileTypeCollection = sourcebip.get('%s/ltm/profile/%s' % (sourceurl_base, typeUrlFragment)).json()
    if profileTypeCollection.get('items'):
        for profile in profileTypeCollection['items']:
            sourceProfileTypeDict[profile['fullPath']] = typeUrlFragment

#print ('sourceProfileDict: %s' % (sourceProfileDict))

sourcePersistenceTypeDict = dict()
sourcePersistenceProfiles = sourcebip.get('%s/ltm/persistence/' % (sourceurl_base)).json()
for persistenceProfile in sourcePersistenceProfiles['items']:
    typeUrlFragment = persistenceProfile['reference']['link'].split("/")[-1].split("?")[0]
    persistenceProfileTypeCollection = sourcebip.get('%s/ltm/persistence/%s' % (sourceurl_base, typeUrlFragment)).json()
    if persistenceProfileTypeCollection.get('items'):
        for persistenceProfile in persistenceProfileTypeCollection['items']:
            sourcePersistenceTypeDict[persistenceProfile['fullPath']] = typeUrlFragment

#print ('sourcePersistenceTypeDict: %s' % (sourcePersistenceTypeDict))

sourceMonitorTypeDict = dict()
sourceMonitors = sourcebip.get('%s/ltm/monitor/' % (sourceurl_base)).json()
for monitor in sourceMonitors['items']:
    typeUrlFragment = monitor['reference']['link'].split("/")[-1].split("?")[0]
    monitorTypeCollection = sourcebip.get('%s/ltm/monitor/%s' % (sourceurl_base, typeUrlFragment)).json()
    if monitorTypeCollection.get('items'):
        for monitor in monitorTypeCollection['items']:
            sourceMonitorTypeDict[monitor['fullPath']] = typeUrlFragment

#print ('sourceMonitorTypeDict: %s' % (sourceMonitorTypeDict))

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

if args.virtual is not None:
    for virtual in args.virtual:
        if virtual in sourceVirtualSet:
            print ('Virtual(s) to copy: %s|whitespacedetector' % (virtual))
            if virtual not in destinationVirtualSet:
                print('Copying virtual: %s' % (virtual))
                copy_virtual(virtual)
            else:
                print('Virtual: %s already present on destination' % (virtual))
        elif virtual in sourceVirtualDict.keys():
            print ('Virtual(s) to copy: %s' % (sourceVirtualDict[virtual]))
            copy_virtual(sourceVirtualDict[virtual])
        else:
            print ('Virtual: %s not found on source BIG-IP' % (virtual))
