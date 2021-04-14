import os
import re
import sys
import csv
import json
import ldap
import uuid
import shutil
import hashlib
import datetime
import subprocess
from six import b, PY2
from time import sleep
import pathos.pools as pp
from struct import unpack, pack
from ese import ESENT_DB
from Cryptodome.Hash import HMAC, MD4
from impacket import winregistry, ntlm
from binascii import unhexlify, hexlify
from impacket.structure import Structure
from impacket.crypto import transformKey
from Cryptodome.Cipher import DES, ARC4, AES
from impacket.examples.secretsdump import LocalOperations
try:
    import configparser
except BaseException:
    import ConfigParser as configparser


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value', '6s'),
    )


class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision', '<B'),
        ('SubAuthorityCount', '<B'),
        ('IdentifierAuthority', ':', SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'),
        ('SubAuthority', ':'),
    )

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'],
                           ord(self['IdentifierAuthority']['Value'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % (unpack('>L',
                                   self['SubAuthority'][i * 4:i * 4 + 4])[0])
        return ans


class CRYPTED_HASH(Structure):
    structure = (
        ('Header', '8s=b""'),
        ('KeyMaterial', '16s=b""'),
        ('EncryptedHash', '16s=b""'),
    )


class CRYPTED_HASHW16(Structure):
    structure = (
        ('Header', '8s=b""'),
        ('KeyMaterial', '16s=b""'),
        ('Unknown', '<L=0'),
        ('EncryptedHash', '32s=b""'),
    )


class PEKLIST_ENC(Structure):
    structure = (
        ('Header', '8s=b""'),
        ('KeyMaterial', '16s=b""'),
        ('EncryptedPek', ':'),
    )


class PEKLIST_PLAIN(Structure):
    structure = (
        ('Header', '32s=b""'),
        ('DecryptedPek', ':'),
    )


class PEK_KEY(Structure):
    structure = (
        ('Header', '1s=b""'),
        ('Padding', '3s=b""'),
        ('Key', '16s=b""'),
    )


class CryptoCommon:
    # Common crypto stuff used over different classes
    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1],
        # I[2], I[3], I[0], I[1]
        key = pack('<L', baseKey)
        key1 = [key[0], key[1], key[2], key[3], key[0], key[1], key[2]]
        key2 = [key[3], key[0], key[1], key[2], key[3], key[0], key[1]]
        if PY2:
            return transformKey(b''.join(key1)), transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)), transformKey(bytes(key2))

    @staticmethod
    def decryptAES(key, value, iv=b'\x00' * 16):
        plainText = b''
        if iv != b'\x00' * 16:
            aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == b'\x00' * 16:
                aes256 = AES.new(key, AES.MODE_CBC, iv)
            cipherBuffer = value[index:index + 16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += b'\x00' * (16 - len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText


class KrakenMaster():
    def __init__(self, domain_config, base_dir, domain):
        self.domain_config = domain_config
        self.base_dir = base_dir
        self.uuid_key = None
        self.data_dir = "{}/data".format(self.base_dir)
        self.base_hash_dir = "{}/hashes".format(self.data_dir)
        self.automated_dir = "{}/automated".format(self.data_dir)
        self.watch_dir = "{}/inbound/".format(self.automated_dir)
        self.status_dir = "{}/status/".format(self.automated_dir)
        self.cracked_dir = "{}/cracked/".format(self.data_dir)
        self.potfiles_dir = "{}/potfiles".format(self.data_dir)
        self.logs_dir = "{}/logs".format(self.base_dir)
        self.charset_dir = "{}/charsets".format(self.data_dir)
        self.wordlist_dir = "{}/wordlists".format(self.data_dir)
        self.rules_dir = "{}/rules".format(self.data_dir)
        self.scripts_dir = "{}/scripts".format(self.base_dir)
        self.hash_dir = "{}/{}".format(self.base_hash_dir, str(uuid.uuid4()))
        self.tmp_workdir1 = "{}/{}/".format(self.hash_dir, str(uuid.uuid4()))
        self.tmp_workdir2 = "{}/{}/".format(self.hash_dir, str(uuid.uuid4()))
        self.kparity_folder = "{}/backup_hashes".format(self.data_dir)
        self.wmiexec_file = "{}/wmiexec.py".format(self.scripts_dir)
        self.hashcat_potfile = "{}/kraken.pot".format(self.potfiles_dir)
        self.hashcat_transforms = "{}/dive.rule".format(self.rules_dir)
        self.hashcat_wordlist = "{}/rockyou.txt".format(self.wordlist_dir)
        self.dropzone_folder = "{}/dropzone".format(self.automated_dir)
        self.domain_dropzone_folder = "{}/{}/".format(
            self.dropzone_folder, domain.lower())
        self.__cryptoCommon = CryptoCommon()
        self.__printUserStatus = True
        self.__pwdLastSet = True
        self.__PEK = list()
        self.__tmpUsers = list()
        self.NAME_TO_INTERNAL = {
            'uSNCreated': b'ATTq131091',
            'uSNChanged': b'ATTq131192',
            'name': b'ATTm3',
            'objectGUID': b'ATTk589826',
            'objectSid': b'ATTr589970',
            'userAccountControl': b'ATTj589832',
            'primaryGroupID': b'ATTj589922',
            'accountExpires': b'ATTq589983',
            'logonCount': b'ATTj589993',
            'sAMAccountName': b'ATTm590045',
            'sAMAccountType': b'ATTj590126',
            'lastLogonTimestamp': b'ATTq589876',
            'userPrincipalName': b'ATTm590480',
            'unicodePwd': b'ATTk589914',
            'dBCSPwd': b'ATTk589879',
            'ntPwdHistory': b'ATTk589918',
            'lmPwdHistory': b'ATTk589984',
            'pekList': b'ATTk590689',
            'supplementalCredentials': b'ATTk589949',
            'pwdLastSet': b'ATTq589920',
        }
        self.SAM_NORMAL_USER_ACCOUNT = 0x30000000
        self.SAM_MACHINE_ACCOUNT = 0x30000001
        self.SAM_TRUST_ACCOUNT = 0x30000002
        self.ACCOUNT_TYPES = (
            self.SAM_NORMAL_USER_ACCOUNT,
            self.SAM_MACHINE_ACCOUNT,
            self.SAM_TRUST_ACCOUNT)
        self.hash_output_file = "{}/{}.txt".format(
            self.hash_dir, str(uuid.uuid4()))
        self.hash_output_end_file = "{}/{}.txt".format(
            self.hash_dir, str(uuid.uuid4()))
        self.smbclient_file = "/usr/bin/smbclient"
        if not os.path.exists(self.smbclient_file):
            raise ("please install smbclient: sudo yum install samba-client")
        self.python_bin = "/usr/local/bin/python"
        self.hashcat_bin = "/usr/local/bin/hashcat"
        self.pool = pp.ProcessPool()
        self.ESEDB = None
        self.cursor = None
        for folder in [
                self.data_dir,
                self.base_hash_dir,
                self.automated_dir,
                self.watch_dir,
                self.status_dir,
                self.cracked_dir,
                self.potfiles_dir,
                self.logs_dir,
                self.charset_dir,
                self.wordlist_dir,
                self.rules_dir,
                self.scripts_dir,
                self.hash_dir,
                self.tmp_workdir1,
                self.tmp_workdir2,
                self.kparity_folder,
                self.dropzone_folder,
                self.domain_dropzone_folder]:
            if not os.path.isdir(folder):
                os.mkdir(folder)
        self.tmp_config = configparser.ConfigParser()
        self.config_file = self.domain_config.get(domain.lower())
        self.tmp_config.read(self.config_file)
        self.base_dn = self.tmp_config.get("base", "base_dn")
        self.dist_name = self.tmp_config.get("base", "dist_name")
        self.dc_host = self.tmp_config.get("base", "hostname")
        self.username = self.tmp_config.get("base", "username")
        self.password = self.tmp_config.get("base", "password")
        self.domain = self.tmp_config.get("base", "domain")
        self.start_time = datetime.datetime.now().isoformat()
        self.linux_ldap_host = self.tmp_config.get("base", "linux_hostname")
        self.linux_ldap_base_dn = self.tmp_config.get("base", "linux_base_dn")
        self.linux_ldap_user_dn = self.tmp_config.get("base", "linux_user_dn")
        self.linux_ldap_password = self.tmp_config.get(
            "base", "linux_password")
        self.gpg_password_file = self.tmp_config.get(
            "base", "pgp_password_file")
        self.gpg_command_path = "/usr/bin/gpg"
        self.alternate_hashcat_job = ""

    def create_workdirs(self):
        for folder in [self.hash_dir, self.tmp_workdir1, self.tmp_workdir2]:
            if not os.path.isdir(folder):
                os.mkdir(folder)
        return True

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        # PEK index can be found on header of each ciphered blob (pos 8-10)
        pekIndex = hexlify(cryptedHash['Header'])
        md5.update(self.__PEK[int(pekIndex[8:10])])
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])
        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1, Key2 = self.__cryptoCommon.deriveKey(int(rid))
        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)
        decryptedHash = Crypt1.decrypt(
            cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])
        return decryptedHash

    def __fileTimeToDateTime(self, t):
        t -= 116444736000000000
        t //= 10000000
        if t < 0:
            return 'never'
        else:
            dt = datetime.datetime.fromtimestamp(t)
            return dt.strftime("%Y-%m-%d %H:%M")

    def __gethivebootkey(self, __systemHive):
        localOperations = LocalOperations(__systemHive)
        bootKey = localOperations.getBootKey()
        return bootKey

    def getPek(self, ntdsFile, systemfile):
        __bootKey = self.__gethivebootkey(systemfile)
        ESEDB = ESENT_DB(ntdsFile, isRemote=False)
        cursor = ESEDB.openTable('datatable')
        peklist = None
        while True:
            try:
                record = ESEDB.getNextRow(cursor)
            except BaseException:
                LOG.error(
                    'Error while calling getNextRow(), trying the next one')
                continue

            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                peklist = unhexlify(record[self.NAME_TO_INTERNAL['pekList']])
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if peklist is not None:
            encryptedPekList = PEKLIST_ENC(peklist)
            if encryptedPekList['Header'][:4] == b'\x02\x00\x00\x00':
                # Up to Windows 2012 R2 looks like header starts this way
                md5 = hashlib.new('md5')
                md5.update(__bootKey)
                for i in range(1000):
                    md5.update(encryptedPekList['KeyMaterial'])
                tmpKey = md5.digest()
                rc4 = ARC4.new(tmpKey)
                decryptedPekList = PEKLIST_PLAIN(
                    rc4.encrypt(encryptedPekList['EncryptedPek']))
                PEKLen = len(PEK_KEY())
                for i in range(
                        len(decryptedPekList['DecryptedPek']) // PEKLen):
                    cursor = i * PEKLen
                    pek = PEK_KEY(
                        decryptedPekList['DecryptedPek'][cursor:cursor + PEKLen])
                    self.__PEK.append(pek['Key'])

            elif encryptedPekList['Header'][:4] == b'\x03\x00\x00\x00':
                # Windows 2016 TP4 header starts this way
                # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
                # using AES:
                # Key: the bootKey
                # CipherText: PEKLIST_ENC['EncryptedPek']
                # IV: PEKLIST_ENC['KeyMaterial']
                decryptedPekList = PEKLIST_PLAIN(
                    self.__cryptoCommon.decryptAES(
                        __bootKey,
                        encryptedPekList['EncryptedPek'],
                        encryptedPekList['KeyMaterial']))

                # PEK list entries take the form:
                #   index (4 byte LE int), PEK (16 byte key)
                # the entries are in ascending order, and the list is terminated
                # by an entry with a non-sequential index (08080808 observed)
                pos, cur_index = 0, 0
                while True:
                    pek_entry = decryptedPekList['DecryptedPek'][pos:pos + 20]
                    if len(pek_entry) < 20:
                        break  # if list truncated, should not happen
                    index, pek = unpack('<L16s', pek_entry)
                    if index != cur_index:
                        break  # break on non-sequential index
                    self.__PEK.append(pek)
                    print("PEK # %d found and decrypted: %s",
                          index, hexlify(pek).decode('utf-8'))
                    cur_index += 1
                    pos += 20

    def decode_name_to_internal(self):
        tmp_dict = {}
        for k, v in self.NAME_TO_INTERNAL.items():
            tmp_dict.update({k: v.decode()})
        self.NAME_TO_INTERNAL_DECODED = tmp_dict

    def process_object_dict(self, record):
        if record:
            if record[self.NAME_TO_INTERNAL_DECODED['userAccountControl']] is not None:
                if '{0:08b}'.format(int(record[self.NAME_TO_INTERNAL_DECODED['userAccountControl']]))[-2:-1] == '0' and '$' not in record[self.NAME_TO_INTERNAL_DECODED['sAMAccountName']
                                                                                                                                          ] and 'HealthMailbox' not in record[self.NAME_TO_INTERNAL_DECODED['sAMAccountName']] and "DEL:" not in record[self.NAME_TO_INTERNAL_DECODED['name']]:
                    print('Decrypting hash for user: %s' %
                          record[self.NAME_TO_INTERNAL_DECODED['name']])
                    sid = SAMR_RPC_SID(unhexlify(
                        record[self.NAME_TO_INTERNAL_DECODED['objectSid']]))
                    rid = sid.formatCanonical().split('-')[-1]
                    if record[self.NAME_TO_INTERNAL_DECODED['dBCSPwd']
                              ] is not None:
                        encryptedLMHash = CRYPTED_HASH(unhexlify(
                            record[self.NAME_TO_INTERNAL_DECODED['dBCSPwd']]))
                        if encryptedLMHash['Header'][:4] == b'\x13\x00\x00\x00':
                            # Win2016 TP4 decryption is different
                            encryptedLMHash = CRYPTED_HASHW16(unhexlify(
                                record[self.NAME_TO_INTERNAL_DECODED['dBCSPwd']]))
                            pekIndex = hexlify(encryptedLMHash['Header'])
                            tmpLMHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                                       encryptedLMHash['EncryptedHash'][:16],
                                                                       encryptedLMHash['KeyMaterial'])
                        else:
                            tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
                        LMHash = self.__removeDESLayer(tmpLMHash, rid)
                    else:
                        LMHash = ntlm.LMOWFv1('', '')

                    if record[self.NAME_TO_INTERNAL_DECODED['unicodePwd']
                              ] is not None:
                        encryptedNTHash = CRYPTED_HASH(unhexlify(
                            record[self.NAME_TO_INTERNAL_DECODED['unicodePwd']]))
                        if encryptedNTHash['Header'][:4] == b'\x13\x00\x00\x00':
                            # Win2016 TP4 decryption is different
                            encryptedNTHash = CRYPTED_HASHW16(unhexlify(
                                record[self.NAME_TO_INTERNAL_DECODED['unicodePwd']]))
                            pekIndex = hexlify(encryptedNTHash['Header'])
                            tmpNTHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                                       encryptedNTHash['EncryptedHash'][:16],
                                                                       encryptedNTHash['KeyMaterial'])
                        else:
                            tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
                        NTHash = self.__removeDESLayer(tmpNTHash, rid)
                    else:
                        NTHash = ntlm.NTOWFv1('', '')

                    if record[self.NAME_TO_INTERNAL_DECODED['userPrincipalName']] is not None:
                        domain = record[self.NAME_TO_INTERNAL_DECODED['userPrincipalName']].split(
                            '@')[-1]
                        userName = '%s\\%s' % (
                            domain, record[self.NAME_TO_INTERNAL_DECODED['sAMAccountName']])
                    else:
                        userName = '%s' % record[self.NAME_TO_INTERNAL_DECODED['sAMAccountName']]

                    if self.__printUserStatus is True:
                        # Enabled / disabled users
                        if record[self.NAME_TO_INTERNAL_DECODED['userAccountControl']] is not None:
                            if '{0:08b}'.format(
                                    record[self.NAME_TO_INTERNAL_DECODED['userAccountControl']])[-2:-1] == '1':
                                userAccountStatus = 'Disabled'
                            elif '{0:08b}'.format(record[self.NAME_TO_INTERNAL_DECODED['userAccountControl']])[-2:-1] == '0':
                                userAccountStatus = 'Enabled'
                        else:
                            userAccountStatus = 'N/A'

                    if record[self.NAME_TO_INTERNAL_DECODED['pwdLastSet']
                              ] is not None:
                        pwdLastSet = self.__fileTimeToDateTime(
                            record[self.NAME_TO_INTERNAL_DECODED['pwdLastSet']])
                    else:
                        pwdLastSet = 'N/A'

                    answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(
                        LMHash).decode('utf-8'), hexlify(NTHash).decode('utf-8'))
                    if self.__pwdLastSet is True:
                        answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
                    if self.__printUserStatus is True:
                        answer = "%s (status=%s)" % (answer, userAccountStatus)
                    with open("{}{}".format(self.tmp_workdir2, str(uuid.uuid4())), "w") as f:
                        f.write("{}".format(answer))

    def process_file(self, filename):
        try:
            with open("{}{}".format(self.tmp_workdir1, filename), 'r') as f:
                record = json.load(f)
                self.process_object_dict(record)
        except Exception as e:
            pass
        return

    def convert_byte_dict(self, data):
        if isinstance(data, bytes):
            return data.decode('ascii')
        if isinstance(data, dict):
            return dict(map(self.convert_byte_dict, data.items()))
        if isinstance(data, tuple):
            return map(self.convert_byte_dict, data)
        return data

    def get_record_data(self, pagedata):
        def get_stuffs(pagedata, tagnum):
            # print("parsing tag {}...".format(tagnum))
            tag = self.ESEDB.getleaf(pagedata, tagnum)
            if tag:
                tagnum += 1
                record = self.ESEDB.tagToRecord(self.cursor, tag['EntryData'])
                if record:
                    if record[self.NAME_TO_INTERNAL['userAccountControl']
                              ] is not None:
                        if '{0:08b}'.format(int(record[self.NAME_TO_INTERNAL['userAccountControl']]))[-2:-1] == '0' and '$' not in record[self.NAME_TO_INTERNAL['sAMAccountName']
                                                                                                                                          ] and 'HealthMailbox' not in record[self.NAME_TO_INTERNAL['sAMAccountName']] and "DEL:" not in record[self.NAME_TO_INTERNAL['name']]:
                            with open('{}{}'.format(self.tmp_workdir1, str(uuid.uuid4())), 'w') as f:
                                f.write(
                                    json.dumps(
                                        self.convert_byte_dict(record)))
                return get_stuffs(pagedata, tagnum)
            return
        try:
            tagnum = 1
            get_stuffs(pagedata, tagnum)
            return
        except BaseException:
            return

    def ntds_decrypt(self, ntdsFile, systemfile):
        try:
            self.decode_name_to_internal()
            self.getPek(ntdsFile, systemfile)
            self.ESEDB = ESENT_DB(ntdsFile, isRemote=False)
            self.cursor = self.ESEDB.openTable('datatable')
            totalpages = self.ESEDB.totalPages
            allpages = self.ESEDB.getPages(totalpages)

            self.pool.map(self.get_record_data, allpages)
            record_jsons = os.listdir(self.tmp_workdir1)
            self.pool.map(self.process_file, record_jsons)
            self.pool.close()
            self.pool.join()
            self.pool.clear()

            contents = os.listdir(self.tmp_workdir2)
            print(contents)
            if contents:
                print(self.hash_output_file)
                with open(self.hash_output_file, 'w') as hf:
                    for filename in contents:
                        with open(os.path.join(self.tmp_workdir2, filename), 'r') as f:
                            hash_line = f.read()
                            hf.write("{}\n".format(hash_line))
            return True
        except Exception as e:
            self.write_log(self.uuid_key, e, overwrite=False)
        return False

    def ad_time_to_seconds(self, ad_time):
        return -(int(ad_time) / 10000000)

    def ad_seconds_to_unix(self, ad_seconds):
        return ((int(ad_seconds) + 11644473600) if int(ad_seconds) != 0 else 0)

    def ad_time_to_unix(self, ad_time):
        ad_seconds = self.ad_time_to_seconds(ad_time)
        return -(self.ad_seconds_to_unix(ad_seconds))

    def write_log(self, uuid_key, logstuff, overwrite=False):
        write_status = 'a'
        if overwrite:
            write_status = 'w'
        with open('{}{}.log'.format(self.status_dir, uuid_key), write_status) as f:
            f.write('{}\n'.format(logstuff))

    def format_hashfile(self, inputFile, outputFile, numDays):
        try:
            regex = re.compile(
                r"(?:(.*)\\)?(.*)\:[0-9]{1,9}\:[a-zA-Z0-9]{32}\:([a-zA-Z0-9]{32})\:\:\:\s\(pwdLastSet\=(?:([0-9]{4}\-[0-9]{2}\-[0-9]{2}\s[0-9]{2}\:[0-9]{2}|never))\)\s\(status\=(Enabled|Disabled)\)")
            with open(outputFile, "w") as out:
                current = datetime.datetime.now()
                with open(inputFile) as inputhandler:
                    lines = [line.rstrip('\n') for line in inputhandler]
                    for line in lines:
                        ln = regex.match(line)
                        if ln:
                            if not ln.group(
                                    2)[-1] == "$":  # strip out computer accounts
                                if ln.group(
                                        5) == "Enabled":  # only enabled accounts
                                    if ln.group(4) == "never":
                                        print(
                                            '%s:%s' %
                                            (ln.group(2), ln.group(3)))
                                        out.write(
                                            '%s:%s\n' %
                                            (ln.group(2), ln.group(3)))
                                    else:
                                        try:
                                            lastSetPwd = datetime.datetime.strptime(
                                                ln.group(4), "%Y-%m-%d %H:%M")
                                        except BaseException:
                                            print("Could not parse date")
                                        lastNumDays = current - \
                                            datetime.timedelta(days=int(numDays))
                                        if lastSetPwd > lastNumDays:
                                            print(
                                                '%s:%s' %
                                                (ln.group(2), ln.group(3)))
                                            out.write(
                                                '%s:%s\n' %
                                                (ln.group(2), ln.group(3)))
                    return True
        except Exception as e:
            print(e)
        return False

    def format_csv(self, inputFile, outputFile, passwd):
        try:
            with open(outputFile, "w") as output:
                with open(inputFile) as input:
                    lines = input.read().splitlines()
                    for line in lines:
                        l = line.split(":")
                        username = l[0]
                        passlen = len(l[1])
                        cracked = l[1]
                        if passwd:
                            output.write(
                                '"{}","{}","{}","{}"\n'.format(
                                    self.domain, username, passlen, cracked))
                        else:
                            output.write(
                                '"{}","{}","{}"\n'.format(
                                    self.domain, username, passlen))
            return True
        except Exception as e:
            print(e)
        return False

    def ldap_lookup(self, inputFile, outputFile):
        if self.base_dn and self.username and self.password and self.dc_host:
            try:
                LDAP_BASE = self.base_dn
                ATTRIBUTES = [
                    "mail",
                    "department",
                    "displayName",
                    "title",
                    "manager",
                    "physicalDeliveryOfficeName",
                    "employeeID",
                    "extensionAttribute13",
                    "pwdLastSet",
                    "distinguishedName",
                    "useraccountcontrol",
                    "lastlogontimestamp"]
                ldap.set_option(
                    ldap.OPT_X_TLS_REQUIRE_CERT,
                    ldap.OPT_X_TLS_NEVER)
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                con = ldap.initialize('ldaps://{}:636'.format(self.dc_host))
                con.simple_bind_s(self.username, self.password)
                with open(outputFile, 'w', newline='\n') as csvoutfile:
                    csv_out_writer = csv.writer(
                        csvoutfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    csv_out_writer.writerow(["Domain",
                                             "Username",
                                             "Password Length",
                                             "Display Name",
                                             "Employee ID",
                                             "Account Type",
                                             "Email",
                                             "Password Last Set",
                                             "Department",
                                             "Title",
                                             "Manager",
                                             "Location",
                                             "UserAccountControl",
                                             "LastLoginTimeStamp"])
                    with open(inputFile, newline='\n') as csvfile:
                        crack_reader = csv.reader(
                            csvfile, delimiter=',', quotechar='"')
                        for line in crack_reader:
                            username = line[1]
                            passlength = line[2]
                            query = "(samaccountname={})".format(username)
                            try:
                                user = con.search_s(
                                    LDAP_BASE, ldap.SCOPE_SUBTREE, query, ATTRIBUTES)[0][1]
                                account_type = ""
                                if 'distinguishedName' in user:
                                    if "Mailboxes" in user['distinguishedName'][0].decode() or "Shared" in user['distinguishedName'][0].decode(
                                    ) or "Service" in user['distinguishedName'][0].decode():
                                        account_type = "Service Account"
                                    elif "admin" in user['distinguishedName'][0].decode() or "Admin" in user['distinguishedName'][0].decode():
                                        account_type = "Admin"
                                    elif "Kiosk" in user['distinguishedName'][0].decode():
                                        account_type = "Kiosk Account"
                                    elif "Test" in user['distinguishedName'][0].decode():
                                        account_type = "Test Account"
                                    elif "Disabled" in user['distinguishedName'][0].decode():
                                        account_type = "Disabled"
                                    elif "Office Name" in user['distinguishedName'][0].decode() or "Users" in user['distinguishedName'][0].decode() or "General" in user['distinguishedName'][0].decode():
                                        account_type = "Employee"
                                pwdLastSet = ""
                                if 'pwdLastSet' in user:
                                    pwdLastSet = datetime.datetime.fromtimestamp(
                                        self.ad_time_to_unix(user['pwdLastSet'][0].decode()))
                                manager = ""
                                if 'manager' in user:
                                    manager = user['manager'][0].decode().split(
                                        ',')[0].decode().replace('CN=', '')
                                display_name = ''
                                if 'displayName' in user:
                                    display_name = user['displayName'][0].decode(
                                    )
                                employee_id = ''
                                if 'employeeID' in user:
                                    employee_id = user['employeeID'][0].decode(
                                    )
                                mail_addr = ''
                                if 'mail' in user:
                                    mail_addr = user['mail'][0].decode()
                                department = ''
                                if 'department' in user:
                                    department = user['department'][0].decode()
                                title = ''
                                if 'title' in user:
                                    title = user['title'][0].decode()
                                office_name = ''
                                if 'physicalDeliveryOfficeName' in user:
                                    office_name = user['physicalDeliveryOfficeName'][0].decode(
                                    )
                                user_account_control = ''
                                if 'userAccountControl' in user:
                                    user_account_control = user['userAccountControl'][0].decode(
                                    )
                                last_logon_timestamp = ''
                                if 'lastLogonTimestamp' in user:
                                    last_logon_timestamp = datetime.datetime.fromtimestamp(
                                        self.ad_time_to_unix(user['lastLogonTimestamp'][0].decode()))
                                csv_out_writer.writerow([
                                    self.domain,
                                    username,
                                    passlength,
                                    display_name,
                                    employee_id,
                                    mail_addr,
                                    pwdLastSet,
                                    department,
                                    title,
                                    manager,
                                    office_name,
                                    user_account_control,
                                    last_logon_timestamp
                                ])
                            except Exception as e:
                                print(e)
                                csv_out_writer.writerow([
                                    self.domain,
                                    username,
                                    passlength,
                                    "",
                                    "",
                                    "",
                                    "",
                                    "",
                                    "",
                                    "",
                                    "",
                                    "",
                                    ""
                                ])
                return True
            except ldap.LDAPError as e:
                print(e)
        return False

    def linux_ldap_lookup(self, inputFile, outputFile):
        if self.linux_ldap_host and self.linux_ldap_base_dn and self.linux_ldap_user_dn:
            try:
                LDAP_BASE = self.linux_ldap_base_dn
                ATTRIBUTES = ["dn", "cn", "uid", "displayName"]
                ldap.set_option(
                    ldap.OPT_X_TLS_REQUIRE_CERT,
                    ldap.OPT_X_TLS_NEVER)
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                con = ldap.initialize('ldaps://{}:636'.format(self.linux_ldap_host))
                con.simple_bind_s(
                    self.linux_ldap_user_dn,
                    self.linux_ldap_password)
                with open(outputFile, 'w', newline='\n') as csvoutfile:
                    csv_out_writer = csv.writer(
                        csvoutfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    csv_out_writer.writerow([
                        "domain",
                        "uid"
                        "displayName",
                        "dn",
                        "cn",
                        "password_length"
                    ])
                    with open(inputFile, newline='\n') as csvfile:
                        crack_reader = csv.reader(
                            csvfile, delimiter=',', quotechar='"')
                        for line in crack_reader:
                            username = line[1]
                            passlength = line[2]
                            query = "(uid={})".format(username)
                            try:
                                user = con.search_s(
                                    LDAP_BASE, ldap.SCOPE_SUBTREE, query, ATTRIBUTES)[0][1]
                                dn = ""
                                if "dn" in user:
                                    dn = user.get("dn")[0].decode()
                                cn = ""
                                if "cn" in user:
                                    cn = user.get("cn")[0].decode()
                                display_name = ""
                                if "displayName" in user:
                                    display_name = user.get("displayName")[0].decode()
                                csv_out_writer.writerow([
                                    self.domain,
                                    username,
                                    display_name,
                                    dn,
                                    cn,
                                    passlength
                                ])
                            except Exception as e:
                                print(e)
                                csv_out_writer.writerow([
                                    self.domain,
                                    username,
                                    "",
                                    "",
                                    "",
                                    passlength
                                ])
                return True
            except ldap.LDAPError as e:
                print(e)
        return False

    def pull_ldap_hashes(self):
        if self.linux_ldap_host and self.linux_ldap_base_dn and self.linux_ldap_user_dn:
            try:
                LDAP_BASE = self.linux_ldap_base_dn
                ATTRIBUTES = ["dn", "userPassword"]
                ldap.set_option(
                    ldap.OPT_X_TLS_REQUIRE_CERT,
                    ldap.OPT_X_TLS_NEVER)
                ldap.set_option(ldap.OPT_REFERRALS, 0)
                con = ldap.initialize(
                    'ldaps://{}:636'.format(self.linux_ldap_host))
                con.simple_bind_s(
                    self.linux_ldap_user_dn,
                    self.linux_ldap_password)
                query = "(objectclass=posixAccount)"
                results = con.search_s(
                    LDAP_BASE, ldap.SCOPE_SUBTREE, query, ATTRIBUTES)
                if results:
                    with open(self.hash_output_end_file, 'w') as f:
                        for result in results:
                            username = result[0].split(
                                ",")[0].replace("uid=", "")
                            password_hash = result[1].get(
                                "userPassword")[0].decode()
                            if username and password_hash:
                                f.write(
                                    "{}:{}\n".format(
                                        username, password_hash))
                    return True
            except ldap.LDAPError as e:
                print(e)
        return False

    def pre_run_clean(self, uuid_key):
        try:
            self.uuid_key = uuid_key
            self.start_time = datetime.datetime.now().isoformat()
            self.write_log(
                uuid_key,
                'Status...........: Running',
                overwrite=True)
            print("checking for old ntds.dit and SYSTEM files...")
            if os.path.exists("{}/ntds.dit".format(self.hash_dir)):
                print("removing old ntds.dit")
                os.remove("{}/ntds.dit".format(self.hash_dir))
            if os.path.exists("{}/SYSTEM".format(self.hash_dir)):
                print("removing old SYSTEM")
                os.remove("{}/SYSTEM".format(self.hash_dir))
            return True
        except BaseException:
            return False

    def pull_ntds_bootkey(self):
        print("create shadow copy")
        cmd_output = subprocess.check_output(
            """{} {} {}:{}@{} "vssadmin create shadow /For=C:" """.format(
                self.python_bin,
                self.wmiexec_file,
                self.username,
                self.password,
                self.dc_host),
            shell=True)
        if cmd_output:
            print("get shadow copy volume name")
            volume_name = [
                re.findall(
                    r'HarddiskVolumeShadowCopy[0-9]{1,3}',
                    l.decode())[0] for l in cmd_output.splitlines() if l.decode().startswith("    Shadow Copy Volume Name: ")]
            print(volume_name)
            if volume_name:
                volume_name = volume_name[0]
                self.write_log(
                    self.uuid_key,
                    "copy ntds.dit file to tmp",
                    overwrite=False)
                copy_exit_code1 = subprocess.call(
                    """{} {} {}:{}@{} "copy \\\\\\?\\GLOBALROOT\\Device\\{}\\windows\\ntds\\ntds.dit C:\\Windows\\Temp\\ " """.format(
                        self.python_bin, self.wmiexec_file, self.username, self.password, self.dc_host, volume_name), shell=True)
                if copy_exit_code1 == 0:
                    self.write_log(
                        self.uuid_key,
                        "copy SYSTEM key to tmp",
                        overwrite=False)
                    copy_exit_code2 = subprocess.call(
                        """{} {} {}:{}@{} "copy \\\\\\?\\GLOBALROOT\\Device\\{}\\windows\\system32\\config\\SYSTEM C:\\Windows\\Temp\\ " """.format(
                            self.python_bin, self.wmiexec_file, self.username, self.password, self.dc_host, volume_name), shell=True)
                    if copy_exit_code2 == 0:
                        self.write_log(
                            self.uuid_key,
                            "pull ntds.dit file back",
                            overwrite=False)
                        transfer1 = subprocess.call(
                            """{} '//{}/c$' -c 'lcd {}; cd /Windows/Temp; get ntds.dit' -A {}""".format(
                                self.smbclient_file, self.dc_host, self.hash_dir, self.config_file), shell=True)
                        if transfer1 == 0:
                            self.write_log(
                                self.uuid_key, "pull SYSTEM file back", overwrite=False)
                            transfer2 = subprocess.call(
                                """{} '//{}/c$' -c 'lcd {}; cd /Windows/Temp; get SYSTEM' -A {}""".format(
                                    self.smbclient_file, self.dc_host, self.hash_dir, self.config_file), shell=True)
                            if transfer2 == 0:
                                self.write_log(
                                    self.uuid_key, "delete shadow copies", overwrite=False)
                                cleanup1 = subprocess.call(
                                    """{} {} {}:{}@{} "vssadmin delete shadows /for=C: /all /quiet" """.format(
                                        self.python_bin,
                                        self.wmiexec_file,
                                        self.username,
                                        self.password,
                                        self.dc_host),
                                    shell=True)
                                if cleanup1 == 0:
                                    self.write_log(
                                        self.uuid_key, "delete ntds.dit file from tmp", overwrite=False)
                                    cleanup2 = subprocess.call(
                                        """{} {} {}:{}@{} "del C:\\Windows\\Temp\\ntds.dit" """.format(
                                            self.python_bin,
                                            self.wmiexec_file,
                                            self.username,
                                            self.password,
                                            self.dc_host),
                                        shell=True)
                                    if cleanup2 == 0:
                                        self.write_log(
                                            self.uuid_key, "delete SYSTEM file from tmp", overwrite=False)
                                        cleanup3 = subprocess.call(
                                            """{} {} {}:{}@{} "del C:\\Windows\\Temp\\SYSTEM" """.format(
                                                self.python_bin,
                                                self.wmiexec_file,
                                                self.username,
                                                self.password,
                                                self.dc_host),
                                            shell=True)
                                        if cleanup3 == 0:
                                            return True
        return False

    def pgp_decrypt_ntds_bootkey(self, ntds_file_path, bootkey_file_path):
        if ntds_file_path and bootkey_file_path:
            self.write_log(
                self.uuid_key,
                "decrypting gpg ntds.dit file...",
                overwrite=False)
            status1 = subprocess.run(
                """{} --decrypt --pinentry-mode loopback --batch --passphrase-file {} {} > {}/ntds.dit""".format(
                    self.gpg_command_path,
                    self.gpg_password_file,
                    ntds_file_path,
                    self.hash_dir),
                shell=True)
            if status1:
                self.write_log(
                    self.uuid_key,
                    "decrypting gpg SYSTEM file...",
                    overwrite=False)
                status2 = subprocess.run(
                    """{} --decrypt --pinentry-mode loopback --batch --passphrase-file {} {} > {}/SYSTEM""".format(
                        self.gpg_command_path,
                        self.gpg_password_file,
                        bootkey_file_path,
                        self.hash_dir),
                    shell=True)
                if status2:
                    return True
        return False

    def run_decrypt_and_format(
            self,
            tmp_ntds=None,
            tmp_bootkey=None,
            decrypt_files=False):
        self.write_log(
            self.uuid_key,
            "decrypt ntds.dit file...",
            overwrite=False)
        ntds_file_path = "{}/ntds.dit".format(self.hash_dir)
        bootkey_file_path = "{}/SYSTEM".format(self.hash_dir)
        if tmp_ntds and tmp_bootkey:
            ntds_file_path = tmp_ntds
            bootkey_file_path = tmp_bootkey
        if decrypt_files:
            self.write_log(
                self.uuid_key,
                "decrypting gpg files...",
                overwrite=False)
            decrypt_status = self.pgp_decrypt_ntds_bootkey(
                ntds_file_path, bootkey_file_path)
            if not decrypt_status:
                return False
            ntds_file_path = "{}/ntds.dit".format(self.hash_dir)
            bootkey_file_path = "{}/SYSTEM".format(self.hash_dir)
        parse_run = self.ntds_decrypt(ntds_file_path, bootkey_file_path)
        if parse_run:
            self.write_log(
                self.uuid_key,
                "formatting hash file...",
                overwrite=False)
            exit_code = self.format_hashfile(
                self.hash_output_file, self.hash_output_end_file, 100000)
            if exit_code:
                self.write_log(
                    self.uuid_key,
                    "copying hash file for kparity analysis later...",
                    overwrite=False)
                today_date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%s-%f')
                kparity_domain_folder = "{}/{}".format(
                    self.kparity_folder, self.domain)
                if not os.path.isdir(kparity_domain_folder):
                    os.mkdir(kparity_domain_folder)
                kparity_file = "{}/{}.txt".format(
                    kparity_domain_folder, today_date)
                shutil.copyfile(self.hash_output_end_file, kparity_file)
                return True
        return False

    def run_hashcat(self, hash_mode=1000, alternate_cmd=None):
        self.write_log(self.uuid_key, "running hashcat...", overwrite=False)
        run_password_crack = "{} -m {} -O -w 4 --username --status --status-timer=15 --potfile-path={} -r {} {} {} >> {}{}.log".format(
            self.hashcat_bin,
            hash_mode,
            self.hashcat_potfile,
            self.hashcat_transforms,
            self.hash_output_end_file,
            self.hashcat_wordlist,
            self.status_dir,
            self.uuid_key)
        if alternate_cmd:
            run_password_crack = alternate_cmd
        run_crack = subprocess.call(run_password_crack, shell=True)
        if run_crack == 0 or run_crack == 1:
            self.write_log(
                self.uuid_key,
                "formatting hashcat output...",
                overwrite=False)
            format_crack_passwords = "{} -m {} --username --potfile-path={} --show -o {}cracked_{}.txt --outfile-format 2 {}".format(
                self.hashcat_bin, hash_mode, self.hashcat_potfile, self.cracked_dir, self.start_time, self.hash_output_end_file)
            format_crack = subprocess.call(format_crack_passwords, shell=True)
            if format_crack == 0:
                self.write_log(
                    self.uuid_key,
                    "formatting csv...",
                    overwrite=False)
                convert_csv_cmd = self.format_csv(
                    "{}cracked_{}.txt".format(
                        self.cracked_dir, self.start_time), "{}cracked_pass_{}.csv".format(
                        self.cracked_dir, self.start_time), False)
                if convert_csv_cmd:
                    self.write_log(
                        self.uuid_key,
                        "removing passwords from csv...",
                        overwrite=False)
                    convert_with_pass_cmd = self.format_csv(
                        "{}cracked_{}.txt".format(
                            self.cracked_dir, self.start_time), "{}cracked_{}.csv".format(
                            self.cracked_dir, self.start_time), True)
                    if convert_with_pass_cmd:
                        return True
        return False

    def run_hashcat_charset_human8(self, hash_mode=1000):
        cmd_string = """{} -a 3 -m {} -O -w 4 --username --status --status-timer=15 --potfile-path={} --increment -1 '?l?u?d._!-@* #/$&\,+=)(??'"'"';]' {} ?1?1?1?1?1?1?1?1 >> {}{}.log""".format(
            self.hashcat_bin,
            hash_mode,
            self.hashcat_potfile,
            self.hash_output_end_file,
            self.status_dir,
            self.uuid_key)
        return self.run_hashcat(hash_mode=hash_mode, alternate_cmd=cmd_string)
    
    def run_hashcat_charset_full8(self, hash_mode=1000):
        cmd_string = """{} -a 3 -m {} -O -w 4 --username --status --status-timer=15 --potfile-path={} --increment {} ?a?a?a?a?a?a?a?a >> {}{}.log""".format(
            self.hashcat_bin,
            hash_mode,
            self.hashcat_potfile,
            self.hash_output_end_file,
            self.status_dir,
            self.uuid_key)
        return self.run_hashcat(hash_mode=hash_mode, alternate_cmd=cmd_string)

    def run_prince_attack(self):
        raise NotImplementedError


    def run_ldap_lookup(self):
        self.write_log(self.uuid_key, "doing ldap lookups...", overwrite=False)
        ldap_lookup_cmd = self.ldap_lookup(
            "{}cracked_{}.csv".format(
                self.cracked_dir, self.start_time), "{}cracked_ldap_{}.csv".format(
                self.cracked_dir, self.start_time))
        if ldap_lookup_cmd:
            return True
        return False
    
    def run_linux_ldap_lookup(self):
        self.write_log(self.uuid_key, "doing ldap lookups...", overwrite=False)
        ldap_lookup_cmd = self.linux_ldap_lookup(
            "{}cracked_{}.csv".format(
                self.cracked_dir, self.start_time), "{}cracked_ldap_{}.csv".format(
                self.cracked_dir, self.start_time))
        if ldap_lookup_cmd:
            return True
        return False

    def write_stats_to_log(self):
        cracked_count = 0
        total_hashes_count = 0
        self.write_log(
            self.uuid_key,
            "gather crack job stats...",
            overwrite=False)
        with open('{}cracked_{}.txt'.format(self.cracked_dir, self.start_time), 'r') as cf:
            cracked_count = len(cf.read().splitlines())
        with open(self.hash_output_end_file, 'r') as hf:
            total_hashes_count = len(hf.read().splitlines())
        self.write_log(
            self.uuid_key,
            'Cracked Count: {}'.format(cracked_count),
            overwrite=False)
        self.write_log(
            self.uuid_key,
            'Total Hashes: {}'.format(total_hashes_count),
            overwrite=False)
        self.write_log(
            self.uuid_key,
            'Status...........: Finished',
            overwrite=False)
        self.write_log(
            self.uuid_key,
            'File Date: {}'.format(
                self.start_time),
            overwrite=False)
        self.write_log(
            self.uuid_key,
            'Start Time: {}'.format(
                self.start_time),
            overwrite=False)
        self.write_log(
            self.uuid_key,
            'End Time: {}'.format(
                datetime.datetime.now().isoformat()),
            overwrite=False)
        try:
            os.remove('{}{}'.format(self.watch_dir, self.uuid_key))
        except Exception as e:
            self.write_log(uuid_key, e, overwrite=False)
        try:
            shutil.rmtree(self.hash_dir)
        except Exception as e:
            self.write_log(uuid_key, e, overwrite=False)
        return True

    def dcsync(self, uuid_key, hash_mode=1000):
        self.uuid_key = uuid_key
        start_time = datetime.datetime.now().isoformat()
        self.write_log(uuid_key, 'Status...........: Running', overwrite=True)
        try:
            result1 = self.pre_run_clean(self.uuid_key)
            if result1:
                result2 = self.pull_ntds_bootkey()
                if result2:
                    result3 = self.run_decrypt_and_format()
                    if result3:
                        if self.alternate_hashcat_job == "full8":
                            result4 = self.run_hashcat_charset_full8(hash_mode)
                        elif self.alternate_hashcat_job == "human8":
                            result4 = self.run_hashcat_charset_human8(hash_mode)
                        else:
                            result4 = self.run_hashcat(hash_mode)
                        if result4:
                            result5 = self.run_ldap_lookup()
                            if result5:
                                result6 = self.write_stats_to_log()
                                if result6:
                                    return True
            self.write_log(
                uuid_key,
                'last cmd didnt exit cleanly',
                overwrite=False)
            self.write_log(
                uuid_key,
                'Status...........: Failed',
                overwrite=False)
            return False
        except Exception as e:
            self.write_log(uuid_key, e, overwrite=False)
        self.write_log(uuid_key, 'Status...........: Failed', overwrite=False)
        return False

    def offline_ad_crack(
            self,
            uuid_key,
            ntds_file_path,
            bootkey_file_path,
            hash_mode=1000,
            decrypt_files=False,
            ldap_lookup=False):
        result1 = self.pre_run_clean(uuid_key)
        if result1:
            result2 = self.run_decrypt_and_format(
                tmp_ntds=ntds_file_path,
                tmp_bootkey=bootkey_file_path,
                decrypt_files=decrypt_files)
            if result2:
                if self.alternate_hashcat_job == "full8":
                    result3 = self.run_hashcat_charset_full8(hash_mode)
                elif self.alternate_hashcat_job == "human8":
                    result3 = self.run_hashcat_charset_human8(hash_mode)
                else:
                    result3 = self.run_hashcat(hash_mode)
                if result3:
                    if ldap_lookup:
                        ldap_result = self.run_ldap_lookup()
                    result4 = self.write_stats_to_log()
                    if result4:
                        return True
        return False

    def live_ad_crack_dictionary(
            self,
            uuid_key,
            hash_mode=1000,
            ldap_lookup=True):
        result1 = self.pre_run_clean(uuid_key)
        if result1:
            result2 = self.pull_ntds_bootkey()
            if result2:
                result3 = self.run_decrypt_and_format()
                if result3:
                    if self.alternate_hashcat_job == "full8":
                        result4 = self.run_hashcat_charset_full8(hash_mode)
                    elif self.alternate_hashcat_job == "human8":
                        result4 = self.run_hashcat_charset_human8(hash_mode)
                    else:
                        result4 = self.run_hashcat(hash_mode)
                    if result4:
                        if ldap_lookup:
                            self.run_ldap_lookup()
                        result5 = self.write_stats_to_log()
                        if result5:
                            return True
        return False

    def live_linux_ldap_crack_dictionary(
            self, uuid_key, hash_mode=111, ldap_lookup=True):
        result1 = self.pre_run_clean(uuid_key)
        if result1:
            result2 = self.pull_ldap_hashes()
            if result2:
                if self.alternate_hashcat_job == "full8":
                    result3 = self.run_hashcat_charset_full8(hash_mode)
                elif self.alternate_hashcat_job == "human8":
                    result3 = self.run_hashcat_charset_human8(hash_mode)
                else:
                    result3 = self.run_hashcat(hash_mode)
                if result3:
                    if ldap_lookup:
                        self.run_linux_ldap_lookup()
                    result5 = self.write_stats_to_log()
                    if result5:
                        return True
        return False


def main():
    # domain to cfg mapping
    with open("./config/default_domain_config.json", "r") as json_file:
        domain_to_config = json.load(json_file)
    # define base dir
    base_dir = domain_to_config.get("basedir")
    # define hashcat path if it needs to be overriden
    hashcat_path = domain_to_config.get("hashcatpath")
    # define smbclient path if it needs to be overriden
    smbclient_path = domain_to_config.get("smbclientpath")
    # define path to python binary
    python_path = domain_to_config.get("pythonpath")
    # through inbound folder is BASE DIR/data/automated/inbound
    # we have to define it here to look at it.
    watch_dir = "{}/data/automated/inbound".format(base_dir)
    # List out all the json files in the dir
    list_dir = os.listdir(watch_dir)
    # open json files
    for filename in list_dir:
        job_file = "{}/{}".format(watch_dir, filename)
        if os.path.isfile(job_file):
            with open(job_file, 'r') as f:
                job_data = json.load(f)
                # parse it to know what kind of job this is
                domain_name = job_data.get("domain")
                # create the obj
                kraken_obj = KrakenMaster(
                    domain_to_config, base_dir, domain_name)
                # hashcat override
                if hashcat_path:
                    kraken_obj.hashcat_bin = hashcat_path
                # smbclient override
                if smbclient_path:
                    kraken_obj.smbclient_file = smbclient_path
                # python override
                if python_path:
                    kraken_obj.python_bin = python_path
                # use the inbound job filename as your uuid
                uuid_key = filename
                crackjob_type = job_data.get("cracktype")
                offline_crack = job_data.get("offline_crack")
                ldap_lookup = job_data.get("ldap_lookup")
                if ldap_lookup is None:
                    ldap_lookup = False
                hash_mode = job_data.get("hash_mode")
                encrypted_files = job_data.get("encrypted")
                dropped_files = job_data.get("dropped_files")
                ntds_file_path = job_data.get("ntds_file_path")
                bootkey_file_path = job_data.get("bootkey_file_path")
                wordlist = job_data.get("wordlist")
                rules = job_data.get("transforms")
                hashes_file = job_data.get("hashes_file")
                alternate_predefined_hashcat_job = job_data.get("althashcatjob")
                if alternate_predefined_hashcat_job:
                    kraken_obj.alternate_hashcat_job = alternate_predefined_hashcat_job
                if crackjob_type == "other":
                    # set self.hash_output_end_file
                    kraken_obj.hash_output_end_file = hashes_file
                    # set wordlist
                    kraken_obj.hashcat_wordlist = wordlist
                    # set rules
                    kraken_obj.hashcat_transforms = rules
                    # run the pre-run cleanup
                    kraken_obj.pre_run_clean(uuid_key)
                    # run run_hashcat
                    kraken_obj.run_hashcat(hash_mode=hash_mode)
                elif crackjob_type == "ad":
                    if offline_crack:
                        if dropped_files:
                            ntds_file_path = "{}ntds.dit".format(
                                kraken_obj.domain_dropzone_folder)
                            bootkey_file_path = "{}SYSTEM".format(
                                kraken_obj.domain_dropzone_folder)
                            if encrypted_files:
                                ntds_file_path = "{}.asc".format(
                                    ntds_file_path)
                                bootkey_file_path = "{}.asc".format(
                                    bootkey_file_path)
                        if ntds_file_path and bootkey_file_path:
                            kraken_obj.offline_ad_crack(
                                uuid_key,
                                ntds_file_path,
                                bootkey_file_path,
                                hash_mode=hash_mode,
                                decrypt_files=encrypted_files,
                                ldap_lookup=ldap_lookup)
                    else:
                        if wordlist:
                            # set wordlist
                            kraken_obj.hashcat_wordlist = wordlist
                        if rules:
                            # set rules
                            kraken_obj.hashcat_transforms = rules
                        kraken_obj.live_ad_crack_dictionary(
                            uuid_key, hash_mode=hash_mode, ldap_lookup=ldap_lookup)
                elif crackjob_type == "ldap":
                    if wordlist:
                        # set wordlist
                        kraken_obj.hashcat_wordlist = wordlist
                    if rules:
                        # set rules
                        kraken_obj.hashcat_transforms = rules
                    kraken_obj.live_linux_ldap_crack_dictionary(
                        uuid_key, hash_mode=hash_mode, ldap_lookup=ldap_lookup)

                del kraken_obj


if __name__ == '__main__':
    while True:
        try:
            main()
        except Exception as e:
            print(e)
        sleep(10)