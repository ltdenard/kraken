# Credits
I want to first put this at the top as I wouldn't be able to even attempt this without the head-start the folks over at Secure Auth Corp gave me with impacket. What their module lacked, I added in. The main item being multiprocessing for large domain ntds.dit files.
https://github.com/SecureAuthCorp/impacket

# What is Kraken?
Kraken is a way to automate cracking jobs, but not just the hashcat part, but also pulling them and formating the hashes to be cracked as well as all the parsing that needs to happen upfront.

# Setup
## install system dependancies
```
sudo yum install samba-client
```
## setup python virtual environment(python 3.9.2)
```
python3.9 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## update your systemd file( krakenworker.service) if you choose to run this as a service
### replace the WorkingDirectory and ExecStart with the correct paths
### install the systemd service file and reload
```
cp ./krakenworker.service /lib/systemd/system/
chmod 644 /lib/systemd/system/krakenworker.service
systemctl daemon-reload
systemctl enabled krakenworker
```

## next, setup the default_domain_config.json
### update the following. you need a mapping for each domain you plan to crack on. 
```
{
    "basedir": "/path/to/kraken",
    "hashcatpath": "/path/to/hashcat",
    "smblcientpath": "/path/to/smbclient",
    "pythonpath": "/path/to/python",
    "example.com": "/path/to/example_creds.cfg"
}
```

## finally, use the default.example to make your .cfg for your domain.
### again, make sure to make a line for each domain. If you have a split domain for linux ldap and windows ldap,
### fill out all fields.
```
[base]
username=Administrator
password=password
domain=example.com
hostname=192.168.1.100
dist_name=CN=Administrator,CN=Users,DC=example,DC=com
base_dn=DC=example,DC=com
linux_hostname=ldap.example.com
linux_base_dn=dc=example,dc=COM
linux_user_dn=cn=admin,dc=example,dc=com
linux_password=password
pgp_password_file=/path/to/password.txt
```

# Using GPG
## generate keys
### this has to be done as the user you plan to run this app as
```
gpg --full-generate-key
```

## export public key
```
gpg --output kraken.pub --armor --export here@there.me
```

## ecrypt file. this produces filename.txt.asc
```
gpg --encrypt --sign --armor -r here@there.me filename.txt
```

## decrypt file
```
gpg --decrypt --pinentry-mode loopback --batch --passphrase-file password.txt filename.txt.asc > filename.txt
```

# Using the Kraken Worker

## Since all jobs are meant to be scheduled, we create a json like one of the following and drop them in 
## $basedir/data/automated/inbound
### current json options
```
{
    "domain":"example.com",
    "cracktype": ad,ldap,other
    "offline_crack": false,
    "ldap_lookup": false,
    "encrypted": false,
    "dropped_files": false,
    "hash_mode": 1000,
    "ntds_file_path": "",
    "bootkey_file_path": "",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "",
    "althashcatjob": full8,human8
}
```

### options for live AD pull and crack
```
{
    "domain":"example.com",
    "cracktype": "ad",
    "offline_crack": false,
    "ldap_lookup": true,
    "encrypted": false,
    "dropped_files": false,
    "hash_mode": 1000,
    "ntds_file_path": "",
    "bootkey_file_path": "",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "",
    "althashcatjob": ""
}
```
### options for an offline AD crack but files where dropped into the dropzone(unencrypted) and doing an ldap lookup
```
{
    "domain":"example.com",
    "cracktype": "ad",
    "offline_crack": true,
    "ldap_lookup": true,
    "encrypted": false,
    "dropped_files": true,
    "hash_mode": 1000,
    "ntds_file_path": "",
    "bootkey_file_path": "",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "",
    "althashcatjob": ""
}
```
### options for a truly disconnected, encrypted files dropped in the dropzone
```
{
    "domain":"example.com",
    "cracktype": "ad",
    "offline_crack": true,
    "ldap_lookup": false,
    "encrypted": true,
    "dropped_files": true,
    "hash_mode": 1000,
    "ntds_file_path": "",
    "bootkey_file_path": "",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "",
    "althashcatjob": ""
}
```
### options for live ldap pull looks like this.
```
{
    "domain":"example.com",
    "cracktype": "ldap",
    "offline_crack": false,
    "ldap_lookup": false,
    "encrypted": false,
    "dropped_files": false,
    "hash_mode": 111,
    "ntds_file_path": "",
    "bootkey_file_path": "",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "",
    "althashcatjob": ""
}
```

### options for other... technically you don't need to have domain cfg setup for other cracks, but it would be useful if you're using the dropzone or GPG encryption
```
{
    "domain":"example.com",
    "cracktype": "other",
    "offline_crack": false,
    "ldap_lookup": false,
    "encrypted": false,
    "dropped_files": false,
    "hash_mode": 1000,
    "ntds_file_path": "/path/to/ntds.dit",
    "bootkey_file_path": "/path/to/system",
    "wordlist": "",
    "transforms": "",
    "hashes_file": "/or/path/to/hashes/file.txt",
    "althashcatjob": ""
}
```


# TODOs
add more stuff like this:
https://github.com/travco/rephraser
