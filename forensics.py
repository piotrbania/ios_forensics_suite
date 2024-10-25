'''


    This is my old forensics project for iOS. 
    - Piotr Bania / https://piotrbania.com 


# iOS Backup Report Generator

This tool generates detailed reports from iOS backups, with support for both unencrypted and encrypted backups (requires password for encrypted ones). It produces responsive reports in web format, as well as PDF or raw JSON files for flexibility. The tool processes data locally, ensuring that your private information remains on your computer.

## Features

The generated report includes the following data extracted from the iOS backup:

- Device details
- Address book contacts
- Calendar events
- WiFi configurations
- Cloud notes
- SMS and text message history
- Stored cookies
- WhatsApp chat data
- File metadata

## System Requirements

- Compatible with **Windows 7/8/10 64-bit**.
- Requires a **modern web browser**.
- Backups can be created using **iTunes** or **iRepair**.
- Supports iOS versions **11, 12, and 13**.




'''







import sqlite3
import plistlib
import re
import hashlib
import os
import shutil
import sys



import json
import zipfile
import base64
import zlib
import time
import platform
import linecache
import binascii
import random
import ctypes
import cffi


from pprint import pprint


from datetime import datetime
from struct import unpack

try:
    from StringIO import StringIO 
except ImportError:
    from io import StringIO 
    from io import BytesIO





from pathlib import Path, PureWindowsPath
import urllib.request as urllib



import warnings
warnings.filterwarnings("ignore",category=DeprecationWarning)


import pkg_resources
import subprocess


required            = {'Crypto', 'fastpbkdf2', 'biplist'}
installed           = {pkg.key for pkg in pkg_resources.working_set}
missing             = required - installed


# to install fastpbkdf2 on windows you need to
# 1) install https://slproweb.com/download/Win64OpenSSL-1_1_1g.exe
# 2) copy include to E:\Python3\
# 3) copy lib to E:\Python3\libs

if missing:
    python = sys.executable
    print("- Warning: some packages are missing: " + ', '.join(missing))
    print("+ Trying to install those packages with pip, if it fails please do this manually")
    
   
    #subprocess.check_call([python, '-m', 'pip', 'install', *missing])    
    #subprocess.check_call(["cmd.exe", "/C", "echo %PATH%"], env=my_env)
    #sys.exit(0)


#import Cryptodome # pip install pycryptodomex or pip install pycryptodome
from Cryptodome.Cipher import AES   # pip install pycryptodomex or pip install pycryptodome



if sys.version[0] == "3":
	unicode = str


__author__      = 'Piotr Bania'
__version__     = '1.0.0'


null            = 0


PBEGIN              =   ''
SEP                 =   '/'
DB_VAR_MARKER       =   'DB_iREPAIR__'  # just some random string for filteirng
DECYRPTED_PREFIX    =   ".DECRYPTED"
IS_DB_ENCRYPTED     =   False


hLib                    = None
TESTFASTPBKDF2_DLL_PATH = "testfastpbkdf2_python64.dll"


if platform.system() == 'Windows':
    #print("+ Running on Windows")
    SEP         =   '\\'
    PBEGIN      =   '\\\\?\\'

    # this is for windows only
    #hDll        =   ctypes.WinDLL(TESTFASTPBKDF2_DLL_PATH)

    ffi          =  cffi.FFI()

    ffi.cdef("""
    void fastpbkdf2_hmac_sha1(const uint8_t *, size_t,
                              const uint8_t *, size_t,
                              uint32_t,
                              uint8_t *, size_t);
    void fastpbkdf2_hmac_sha256(const uint8_t *, size_t,
                                const uint8_t *, size_t,
                                uint32_t,
                                uint8_t *, size_t);
    void fastpbkdf2_hmac_sha512(const uint8_t *, size_t,
                                const uint8_t *, size_t,
                                uint32_t,
                                uint8_t *, size_t);
    """)

    hLib         =  ffi.dlopen(TESTFASTPBKDF2_DLL_PATH)
    

algorithm = {
    "sha1":     (hLib.fastpbkdf2_hmac_sha1, 20),
    "sha256":   (hLib.fastpbkdf2_hmac_sha256, 32),
    "sha512":   (hLib.fastpbkdf2_hmac_sha512, 64),
}


def pbkdf2_hmac(name, password, salt, rounds, dklen=None):
    

    print('+ Using Password = %s / len = %d' % (str(password), len(password) ))


    if not isinstance(password, bytes):
        password = password.encode('ascii')

    try:

        if name not in ["sha1", "sha256", "sha512"]:
            raise ValueError("unsupported hash type")

        out_length   = dklen or algorithm[name][1]
        out          = ffi.new("uint8_t[]", out_length)

        algorithm[name][0](
            password, len(password),
            salt, len(salt),
            rounds,
            out, out_length
        )

        return ffi.buffer(out)[:]

    except:
        PrintException()
        return False










db_files        =   [   'KeychainDomain-keychain-backup.plist',								# 51a4616e576dd33cd2abadfea874eb8ff246bf0e
                        'HomeDomain-Library/Safari/History.plist',
                        'HomeDomain-Library/Preferences/com.apple.springboard.plist',
                        'HomeDomain-Library/SMS/sms.db',									# 3d0d7e5fb2ce288813306e4d4636395e047a3d28
                        'HomeDomain-Library/AddressBook/AddressBook.sqlitedb',				# 31bb7ba8914766d4ba40d6dfb6113c8b614be442
                        'HomeDomain-Library/AddressBook/AddressBookImages.sqlitedb',     	# cd6702cea29fe89cf280a76794405adb17f9a0ee
                        'WirelessDomain-Library/CallHistory/call_history.db',				# 2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca
                        'HomeDomain-Library/Notes/notes.sqlite',							# ca3bc056d4da0bbf88b5fb3be254f3b7147e639c
                        'HomeDomain-Library/Calendar/Calendar.sqlitedb',					# 2041457d5fe04d39d0ab481178355df6781e6858
                        'HomeDomain-Library/Voicemail/voicemail.db',						# 992df473bbb9e132f4b3b6e4d33f72171e97bc7a
                        'CameraRollDomain-Media/PhotoData/Photos.sqlite',					# 12b144c0bd44f2b3dffd9186d3f9c05b917cee25
                        'MediaDomain-Media/Recordings/Recordings.db',						# 303e04f2a5b473c5ca2127d65365db4c3e055c05
                        'HomeDomain-Library/Safari/Bookmarks.db']



db_SMS                      =       'HomeDomain-Library/SMS/sms.db'
db_AddressBook              =       'HomeDomain-Library/AddressBook/AddressBook.sqlitedb'
db_Calendar                 =       'HomeDomain-Library/Calendar/Calendar.sqlitedb'	
db_Notes                    =       'HomeDomain-Library/Notes/notes.sqlite'	
db_CloudNotes               =       'AppDomainGroup-group.com.apple.notes-NoteStore.sqlite'
db_CallHistory              =       'WirelessDomain-Library/CallHistory/call_history.db'
db_WhatsApp                 =       'AppDomainGroup-group.net.whatsapp.WhatsApp.shared-ChatStorage.sqlite'


bin_cookies                 =       'AppDomain-com.apple.mobilesafari-Library/Cookies/Cookies.binarycookies'


plist_WiFi                  =       'SystemPreferencesDomain-SystemConfiguration/com.apple.wifi.plist'



db_AddressBook_file         =   0
db_SMS_file                 =   0
db_Calendar_file            =   0
db_Notes_file               =   0
db_CloudNotes_file          =   0
db_WhatsApp_file            =   0

plist_WiFi_file             =   0
bin_cookies_file            =   0


dateEpoch2001 = lambda ts: datetime.utcfromtimestamp(978307200 + ts)




DEBUG_MODE                    =   1







#
#
# ENCRYPTED BACKUPs SUPPORT
#
#

# this section is mostly copied from parts of iphone-dataprotection
# http://code.google.com/p/iphone-dataprotection/

import struct

CLASSKEY_TAGS = [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"] 
KEYBAG_TYPES = ["System", "Backup", "Escrow", "OTA (icloud)"]
KEY_TYPES = ["AES", "Curve25519"]
PROTECTION_CLASSES={
    1:"NSFileProtectionComplete",
    2:"NSFileProtectionCompleteUnlessOpen",
    3:"NSFileProtectionCompleteUntilFirstUserAuthentication",
    4:"NSFileProtectionNone",
    5:"NSFileProtectionRecovery?",

    6: "kSecAttrAccessibleWhenUnlocked",
    7: "kSecAttrAccessibleAfterFirstUnlock",
    8: "kSecAttrAccessibleAlways",
    9: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    10: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    11: "kSecAttrAccessibleAlwaysThisDeviceOnly"
}
WRAP_DEVICE = 1
WRAP_PASSCODE = 2

ANONYMIZE_OUTPUT = 0

class Keybag(object):
    def __init__(self, data):
        self.type = None
        self.uuid = None
        self.wrap = None
        self.deviceKey = None
        self.attrs = {}
        self.classKeys = {}
        self.KeyBagKeys = None #DATASIGN blob
        self.parseBinaryBlob(data)

    def parseBinaryBlob(self, data):
        currentClassKey = None

        for tag, data in loopTLVBlocks(data):
            #print("DEBUG: tag=%s" % tag)

            if len(data) == 4:
                data = struct.unpack(">L", data)[0]


            if tag == b"TYPE":
                self.type = data
                if self.type > 3:
                    print("FAIL: keybag type > 3 : %d" % self.type)
            elif tag == b"UUID" and self.uuid is None:
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == b"UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
                currentClassKey = {b"UUID": data}
            elif tag in CLASSKEY_TAGS:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey

    def unlockWithPasscode(self, passcode, passcode_key=None):
        global hLib
        try:

            if passcode_key is None:
       
                passcode1       = pbkdf2_hmac('sha256', passcode,
                                                self.attrs[b"DPSL"],
                                                self.attrs[b"DPIC"], 32)


                passcode_key    = pbkdf2_hmac('sha1', passcode1,
                                                    self.attrs[b"SALT"],
                                                    self.attrs[b"ITER"], 32)
            print('== Passcode key')
            print(anonymize(binascii.hexlify(passcode_key)))



            #print('== Pasccode key ascii: ' + passcode_key.encode('utf-8'))

            for classkey in self.classKeys.values():
                if b"WPKY" not in classkey:
                    continue
                k = classkey[b"WPKY"]
                if classkey[b"WRAP"] & WRAP_PASSCODE:
                    k = AESUnwrap(passcode_key, classkey[b"WPKY"])
                    if not k:
                        return False
                    classkey[b"KEY"] = k

        except:
            PrintException()

        return True

    def unwrapKeyForClass(self, protection_class, persistent_key):
        ck = self.classKeys[protection_class][b"KEY"]
        if len(persistent_key) != 0x28:
            raise Exception("Invalid key length")
        return AESUnwrap(ck, persistent_key)

    def printClassKeys(self):

        try:
            print("== Keybag")
            print("Keybag type: %d" % self.type)
            print("Keybag type: %s keybag (%d)" % (KEYBAG_TYPES[self.type], self.type))
        
            print("Keybag version: %d" % self.attrs[b"VERS"])
            print("Keybag UUID: %s" % anonymize(binascii.hexlify(self.uuid, ' ')))
            print("-"*209)
            print("".join(["Class".ljust(53),
                          "WRAP".ljust(5),
                          "Type".ljust(11),
                          "Key".ljust(65),
                          "WPKY".ljust(65),
                          "Public key"]))
            print("-"*208)
            for k, ck in self.classKeys.items():
                if k == 6:print("")

                __WRAP      = ck.get(b"WRAP",  "")
                __KTYP      = ck.get(b"KTYP",  0)
                __KEY       = ck.get(b"KEY",   b"")
                __WPKY      = ck.get(b"WPKY",  b"")


                
                #print("__KTYP   = %d" %     __KTYP)
                #print("__KEY    = " +       str(binascii.hexlify(__KEY)))
                #print("__WPKY   = " +       str(binascii.hexlify(__WPKY)))


                
                print("".join(
                    [PROTECTION_CLASSES.get(k).ljust(53),
                    str(__WRAP).ljust(5),
                    KEY_TYPES[__KTYP].ljust(11),
                    anonymize(str(binascii.hexlify(__KEY))).ljust(65),
                    anonymize(str(binascii.hexlify(__WPKY))).ljust(65),
                ]))
            print()

        except:
            PrintException()

def loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i+4]
        length = struct.unpack(">L",blob[i+4:i+8])[0]
        data = blob[i+8:i+8+length]
        yield (tag,data)
        i += 8 + length

def unpack64bit(s):
    return struct.unpack(">Q",s)[0]
def pack64bit(s):
    out = struct.pack(">Q",s)
    #pprint(out)
    return out


def AESUnwrap(kek, wrapped):

    try:
        C = []
        for i in range(len(wrapped) // 8):
            C.append(unpack64bit(wrapped[i*8:i*8+8]))
        n = len(C) - 1
        R = [0] * (n+1)
        A = C[0]

        for i in range(1, n+1):
            R[i] = C[i]


        for j in reversed(range(0,6)):
            for i in reversed(range(1,n+1)):
                todec   =   pack64bit(A ^ (n*j+i))
                todec   +=  pack64bit(R[i])
                #B = Cryptodome.Cipher.AES.new(kek).decrypt(todec)
                
                B           = AES.new(kek, AES.MODE_ECB).decrypt(todec)

                A           = unpack64bit(B[:8])
                R[i]        = unpack64bit(B[8:])


        
        if A != 0xa6a6a6a6a6a6a6a6:
            return None

        res = b"".join(map(pack64bit, R[1:]))
        return res

    except:
        PrintException()
        return False





ZEROIV = b"\x00"*16
def AESdecryptCBC(data, key, iv=ZEROIV, padding=False):
    if len(data) % 16:
        print("- Error: AESdecryptCBC: data length not /16, truncating")
        data = data[0:(len(data)/16) * 16]



    try:

        #data = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(data)

        #pprint(ZEROIV)
        data = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        if padding:
            return removePadding(16, data)

        #print("+ AESdecryptCBC returned=")
        #pprint(data)
        return data
    except:
        PrintException()
        return False






##
# here are some utility functions, one making sure I don’t leak my
# secret keys when posting the output on Stack Exchange

anon_random = random.Random(0)
memo = {}
def anonymize(s):
    global anon_random, memo
    if ANONYMIZE_OUTPUT:
        if s in memo:
            return memo[s]
        possible_alphabets = [
            string.digits,
            string.digits + 'abcdef',
            string.letters,
            "".join(chr(x) for x in range(0, 256)),
        ]
        for a in possible_alphabets:
            if all(c in a for c in s):
                alphabet = a
                break
        ret = "".join([anon_random.choice(alphabet) for i in range(len(s))])
        memo[s] = ret
        return ret
    else:
        return s

def wrap(s, width=78):
    "Return a width-wrapped repr(s)-like string without breaking on \’s"
    s = repr(s)
    quote = s[0]
    s = s[1:-1]
    ret = []
    while len(s):
        i = s.rfind('\\', 0, width)
        if i <= width - 4: # "\x??" is four characters
            i = width
        ret.append(s[:i])
        s = s[i:]
    return '\n'.join("%s%s%s" % (quote, line ,quote) for line in ret)


def removePadding(data, blocksize=16):
    n = int(data[-1])  # RFC 1423: last byte contains number of padding bytes.
    if n > blocksize or n > len(data):
        raise Exception('Invalid CBC padding')
    return data[:-n]







def readBackupEncrypted(BackupPath, OutPath, OutPathReport, Password):


    
    ManifestPlistPath   =   pathConvert(os.path.join(BackupPath, 'Manifest.plist'))
    dbPath              =   pathConvert(os.path.join(BackupPath, 'Manifest.db'))
    outJSON             =   pathConvert(os.path.join(OutPathReport, 'Info.json'))
    dbDecryptedPath     =   pathConvert(os.path.join(BackupPath, 'Manifest.db' + DECYRPTED_PREFIX))


    try:

        with open(ManifestPlistPath, 'rb') as f:
            info             =   plistlib.load(f)
        
        IsEncrypted      =   info.get('IsEncrypted')
        BackupKeyBag     =   info.get('BackupKeyBag')
        BackupKeyBagAsc  =   str(binascii.hexlify(BackupKeyBag, ' '))
        ManifestKey      =   info.get('ManifestKey')



        ManifestKeyAsc   =   str(binascii.hexlify(ManifestKey, ' '))


        keybag           =   Keybag(BackupKeyBag)
        keybag.printClassKeys()



        passcode_key     =    None

        
        if not keybag.unlockWithPasscode(Password, passcode_key):
            print("- Error: could not unlock keybag, bad password?")
            return False

        keybag.printClassKeys()




        ## Decrypt metadata DB
        ManifestKeyG     = ManifestKey[4:]
        with open(dbPath, 'rb') as db:
            encrypted_db = db.read()

        manifest_class      = struct.unpack('<l', ManifestKey[:4])[0]
        key                 = keybag.unwrapKeyForClass(manifest_class, ManifestKeyG)
        decrypted_manifest  = AESdecryptCBC(encrypted_db, key)


        print("+ Storing decrypted manifest to \"%s\" " % dbDecryptedPath)
        with open(dbDecryptedPath, 'wb') as f:
            f.write(decrypted_manifest)



        # decrypt them files
        print("+ Decrypting all files")


        try:
                conn    = sqlite3.connect(dbDecryptedPath)
                c       = conn.cursor()

                # get all files
                files       = c.execute('SELECT fileID, relativePath, domain, file from Files WHERE flags IS 1').fetchall()
              
                for item in files:
                    fileID, relativePath, domain, file_bplist = item

                    plist               =     plistlib.loads(file_bplist)
                    FileData            =     plist['$objects'][plist['$top']['root']]
                    FileSize            =     FileData['Size']
                    
                    EncryptionKey       =     plist['$objects'][FileData['EncryptionKey']]['NS.data'][4:]
                    ProtectionClass     =     FileData['ProtectionClass']

                    
                    # decrypt this file
                    EncryptedFilePath   =     pathConvert(os.path.join(BackupPath, fileID[:2], fileID))
                    DecryptedFilePath   =     pathConvert(os.path.join(BackupPath, fileID[:2], fileID + DECYRPTED_PREFIX))


                    

                    with open(EncryptedFilePath, 'rb') as infile:
                        data            = infile.read()
                        key             = keybag.unwrapKeyForClass(ProtectionClass, EncryptionKey)
                        decrypted_data  = AESdecryptCBC(data, key)  #[:FileSize]       # skip the padding
                        
                        # now decrypted_data should be padded to FileSize however if we do that
                        # some sqlite databases (ie. notes) will be damaged, ugh dont skip the pad for now
                        
                        #if len(decrypted_data) != FileSize:
                            #print("Size mismatch len=%d vs FileSize=%d" % (len(decrypted_data), FileSize))
                            #decrypted_data  = AESdecryptCBC(data, key)[:FileSize]  


                        decrypted_data   = removePadding(decrypted_data)

                    # write decrypted file
                    with open(DecryptedFilePath, 'wb') as outfile:
                        outfile.write(decrypted_data)


                    
                    #print("EncryptedFilePath = %s / RelativePath = %s / EncryptionKey = %s / ProtectionClass = %d" % (EncryptedFilePath, relativePath, EncryptionKey, ProtectionClass))
                    #print("Decrypted to = %s - filesize: %d" % (DecryptedFilePath, os.path.getsize(DecryptedFilePath)))
                    #pprint(FileData)
                    #sys.exit(0)


        except:
                print('! Error: opening backup database - path = \"%s\"' % dbPath)
                print('! Error: please make sure this DB is not encrypted')
                PrintException()
                return False




        print("Done")



    except:
        print('! Error: opening Manifest.plist - path = \"%s\"' % ManifestPlistPath)
        PrintException()
        return False

    return True









#
#
# END OF ENCRYPTION/DECRYPTION SUPPORT
#
#



def PrintException():
    if DEBUG_MODE == 0:
        return 0

    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('- Error: EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))



def isset(var):
    try: var
    except: return False
    else: return True

def get_date(mdate):
	# convert apple's "reference date" to unix timestamp
	# (seconds between Jan 1 1970 and Jan 1 2001)
	# http://stackoverflow.com/questions/6998541


    try:
        mdate       = int(mdate) + 978307200
        mdatetime   = datetime.fromtimestamp(mdate)
        mdatetime   = mdatetime.strftime("%Y-%m-%d %H:%M:%S")
	
    except Exception as e:
        print('- Error: unable to decode date: {}'.format(e))
        print('- Error: problematic timestamp mdate=%s' % mdate)
        PrintException()
        return "0000-00-00 00:00:00"
        
    return mdatetime


def sanitize_filename(f):
	invalid_chars = "?*/\\:\"<>|"
	for char in invalid_chars:
		f = f.replace(char, "-")
	return f

def sanitize_filename2(f):
	invalid_chars = "?*:\"<>|"

	if (len(f) < 8):
		return f

	f_part          = f[:8]
	ff              = f[8:]

	for char in invalid_chars:
		ff = ff.replace(char, "-")

	ff = ff.replace("\\\\", "-")
	ff = f_part + ff

	#print("before = %s       after=%s" % (f, ff))
	return ff


# taken from https://www.alfredforum.com/topic/11716-search-appleicloud-notes/page/2/
def extractNoteBody(data):
    try:
        

        # Strip weird characters, title & weird header artifacts, 
        # and replace line breaks with spaces

        
        data = zlib.decompress(data, 16+zlib.MAX_WBITS)

     
        data = data.decode('unicode_escape', errors="ignore").encode('utf-8', errors="ignore")
        data = data.decode().split('\x1a\x10', 1)[0]



        # Reference: https://github.com/threeplanetssoftware/apple_cloud_notes_parser
        # Find magic hex and remove it
        index = data.index('\x08\x00\x10\x00\x1a')
        index = data.index('\x12', index)

        

        # Read from the next byte after magic index
        data = data[index+1:]

        #data = unicode(data, "utf8", errors="ignore")
        data = data.encode("utf8", errors="ignore")


        return re.sub('^.*\n|\n', ' ', data.decode())

    except Exception as e:
        print('- Error: Note body could not be extracted: {}'.format(e))
        PrintException()
        return 'Note body could not be extracted: {}'.format(e)
    


def isBackup(BackupPath):
        '''
        Check if path contains backup
        (files below should be always available in the correct backup directory)

        ''' 
        if os.path.isdir(BackupPath):
                content = os.listdir(BackupPath)
                return ('Manifest.db' in content and 'Info.plist' in content) or ('Status.plist' in content and 'Snapshot' in content)
        return False


def pathConvert(path):
    path        =   str(path)
    if path.find('\\\\') == -1:
        path = PBEGIN + path



   # path    =   "\\\\?\\C:\\out\\AppDomain-im.vector.app\\Library\\Preferences\\1https:\\\\dupa"  


    path    =   path.replace('sceneID:', 'sceneID_BAD1_')          # replace bad chars
    path    =   sanitize_filename2(path)
    #sys.exit(0)

    path    =   Path(path) # conver to OS format
    return path



# Get full path for selected database file
def pathDBOut(Conn, OutPath, FileName):
    FileIDHash  =    hashlib.sha1(str(FileName).encode('utf-8')).hexdigest()
    c           =    Conn.cursor()    
    file        =    c.execute('SELECT domain, relativePath from Files WHERE (flags IS 1) AND (fileID == "' + FileIDHash + '")').fetchone()

    if file == None:
        print("! Error: unable to find %s in db" % FileName)
        return False

    #out         =   OutPath + '\\' + file[0] + '\\' + file[1]

    out         =   os.path.join(OutPath, file[0])
    out         =   os.path.join(out, file[1])

    out         =   pathConvert(out)

    #print(out)
    return out


def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()




def extract(Conn, BackupPath, OutPath, outJSON, isEncrypted):
    
    c           =    Conn.cursor()    
        
    print('+ Getting information about directories')
    all_dirs    =    c.execute('SELECT * FROM Files WHERE flags IS 2').fetchall() 



    for id_, domain, file, flag, f in all_dirs:
		
        d1  =   pathConvert(os.path.join(OutPath, domain))
        d2  =   pathConvert(os.path.join(OutPath, domain, file))

       # print('d1 = %s' % d1)
       # print('d2 = %s' % d2)
    
        try:
            if not os.path.isdir(d1):
                os.makedirs(d1)
            if not os.path.isdir(d2):
                os.makedirs(d2)

        except OSError as err:
            print('! Error: during directory creation ' + str(err))
            #sys.exit(0)



    print('+ Directories created')

    all_files       =   c.execute('SELECT * FROM Files WHERE flags IS 1').fetchall()
    total_files     =   float(len(all_files))
    counter         =   1

    print('+ Detected %d files' % total_files)


    # extract them


    item        =   {}
    f_out       =    open(outJSON, 'w')


    db_name = ' \n { \t"fileinfo_' + DB_VAR_MARKER + '": [\n'
    f_out.write(db_name)


    for id_, domain, file, flag, f in all_files:

        if flag == 1:
            path_split      =   os.path.split(file)
            sub_dir         =   id_[:2]

            #print('PathSplit=%s sub_dir=%s file=%s id=%s' % (path_split, sub_dir, file, id_))

            path_src       =    pathConvert(os.path.join(BackupPath, sub_dir, id_))
            path_dest      =    pathConvert(os.path.join(OutPath, domain, file))

            if isEncrypted == True:
                path_src       =    pathConvert(os.path.join(BackupPath, sub_dir, id_ + DECYRPTED_PREFIX))




            #print('PathSrc=%s PathDest=%s ' % (path_src, path_dest))
            #sys.exit(0)

            try:


                pl      =   plistlib.loads(f)
                plx     =   pl.get('$objects')[1]
                #print(plx)
          

                _creationTime           =   null
                _accessTime             =   null
                _modTime                =   null
               
                if ('Birth'                         in plx):              _creationTime              = plx['LastModified']
                if ('LastStatusChange'              in plx):              _accessTime                = plx['LastStatusChange']
                if ('LastModified'                  in plx):              _modTime                   = plx['LastModified']



                #print('+ Copying (%d/%d) \"%s\" to \"%s\" ' % (counter, total_files, file, path_dest))

                # 
                # get details about the file
                # id_, domain, name, path, sha256, size, created, modified, accessed
                # 
                
                _name           =   os.path.basename(path_src)
                _sha256         =   sha256sum(path_src)
                _size           =   os.path.getsize(path_src)
                
                _creationTime   =   time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_creationTime))
                _accessTime     =   time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_accessTime))
                _modTime        =   time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_modTime))



                item    = {         'id'                    : id_,
                                    'name'                  : _name,
                                    'domain'                : domain,
                                    'path'                  : file,
                                    'pathBackup'            : path_src,
                                    'pathOnDisk'            : path_dest,
                                    'sha256'                : _sha256,
                                    'size'                  : _size,
                                    'creationTime'          : _creationTime,
                                    'modificationTime'      : _modTime,
                                    'accessTime'            : _accessTime }

                json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
                f_out.write(",")


                #print('+ Copying (%d/%d) \"%s\" to \"%s\" ' % (counter, total_files, file, path_dest))
                #shutil.copytree(path_src, path_dest, dirs_exist_ok=True) 
                shutil.copy(path_src, path_dest) 

                #print("+ Copied")



                counter     =   counter + 1
            except Exception as err:
                print('! Error: unable to copy \"%s\" to \"%s\", error = %s ' % (path_src, path_dest, str(err)))
                PrintException()
            

    #finish json with empty entry
    for key in item.keys():
        item[key]   =   null
    
    json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
    f_out.write("]}\n\n\n")
    f_out.close()
    




#
#
# CheckBackupEncryption
#
#


def checkBackupEncryption(ManifestPlistPath):

    try:

       with open(ManifestPlistPath, 'rb') as f:
           info             =   plistlib.load(f)
           IsEncrypted      =   info.get('IsEncrypted')
           BackupKeyBag     =   info.get('BackupKeyBag')
           BackupKeyBagAsc  =   str(binascii.hexlify(BackupKeyBag, ' '))
           ManifestKey      =   info.get('ManifestKey')
           ManifestKeyAsc   =   str(binascii.hexlify(ManifestKey, ' '))


           if IsEncrypted == True:
               print('- Warning: this backup is encrypted')
               print('- BackupKeyBag: ' + BackupKeyBagAsc)
               print('- ManifestKey: ' + ManifestKeyAsc)
               return True
           else:
               print('+ This backup is not encrypted')
               return False





    except:
        print('! Error: opening Manifest.plist - path = \"%s\"' % ManifestPlistPath)
        PrintException()
        return False



#
#
# readBackup
#
#


def readBackup(BackupPath, OutPath, OutPathReport, Password):
        global IS_DB_ENCRYPTED
        global db_AddressBook_file, db_SMS_file, db_Calendar_file, db_Notes_file
        global db_CloudNotes_file, db_SMS_file, plist_WiFi_file
        global bin_cookies_file, db_WhatsApp_file




        plistPath   =   pathConvert(os.path.join(BackupPath, 'Manifest.plist'))
        dbPath      =   pathConvert(os.path.join(BackupPath, 'Manifest.db'))
        outJSON     =   pathConvert(os.path.join(OutPathReport, 'Info.json'))



        if checkBackupEncryption(plistPath) == True:
            readBackupEncrypted(BackupPath, OutPath, OutPathReport, Password)

            IS_DB_ENCRYPTED     =   True
            dbPath              =   pathConvert(os.path.join(BackupPath, 'Manifest.db' + DECYRPTED_PREFIX))
            
            print("- Warning: this backup is encrypted, quitiing, trying to decrypt with password: \"%s\"" % Password)




            #return False


        try:
                conn    = sqlite3.connect(dbPath)
                c       = conn.cursor()

                # get all files
                files       = c.execute('SELECT fileID, relativePath, domain from Files WHERE flags IS 1').fetchall()
                #print (''.join(map(lambda s: '[%s]  %s : %s\n'%(s[2],s[0],s[1]),files)))
        except:
                print('! Error: opening backup database - path = \"%s\"' % dbPath)
                print('! Error: please make sure this DB is not encrypted')
                PrintException()
                return False


        OutPathFilesInfo     =   pathConvert(os.path.join(OutPathReport, 'FilesInfo.json'))
        extract(conn, BackupPath, OutPath, OutPathFilesInfo, IS_DB_ENCRYPTED)



        # read device info

        infoPlistPath           =   (os.path.join(BackupPath, 'Info.plist'))    # this is not encrypted even in encrypted backups
        #print(infoPlistPath)

        try:
            with open(infoPlistPath, 'rb') as f:
                 info = plistlib.load(f)
           
            
            #info = plistlib.load(f)

      
            m = re.match("(.*?)\d", info['Product Type'])
            serviceType         = m.group(1)

            out                 =  {}
            out['device_info']  = []

            deviceName          = "UNKNOWN"
            productType         = "UNKNOWN"
            productVersion      = "UNKNOWN"
            serialNumber        = "UNKNOWN"
            imei                = "UNKNOWN"
            lastBackupDate      = "UNKNOWN"
            targetIdentifier    = "UNKNOWN"
            phoneNumber         = "UNKNOWN"
            buildVersion        = "UNKNOWN"


            if ('Device Name' in info):             deviceName          = info['Device Name']
            if ('Product Type' in info):            productType         = info['Product Type'].replace(',', '').lower()
            if ('Product Version' in info):         productVersion      = info['Product Version']
            if ('Serial Number' in info):           serialNumber        = info['Serial Number']
            if ('IMEI' in info):                    imei                = info['IMEI']
            if ('Last Backup Date' in info):        lastBackupDate      = info['Last Backup Date']
            if ('Target Identifier' in info):       targetIdentifier    = info['Target Identifier']
            if ('Phone Number' in info):            phoneNumber         = info['Phone Number']
            if ('Build Version' in info):           buildVersion        = info['Build Version']
            

            out_json = {
                'deviceName':deviceName,
                'productType':productType,
                'productVersion':productVersion,
                'serialNumber':serialNumber,
                'imei':imei,
                'lastBackupDate':lastBackupDate,
                'targetIdentifier':targetIdentifier,
                'phoneNumber':phoneNumber,
                'buildVersion':buildVersion 
                }

            out['device_info'].append({'deviceName':deviceName})
            out['device_info'].append({'productType':productType})
            out['device_info'].append({'productVersion':productVersion})
            out['device_info'].append({'serialNumber':serialNumber})
            out['device_info'].append({'imei':imei})
            out['device_info'].append({'lastBackupDate':lastBackupDate})
            out['device_info'].append({'targetIdentifier':targetIdentifier})
            out['device_info'].append({'phoneNumber':phoneNumber})
            out['device_info'].append({'buildVersion':buildVersion})

            #print(out)


            
            
            with open(outJSON, 'w') as outfile:
                db_name = ' { "info_' + DB_VAR_MARKER + '": ['
                outfile.write(db_name)
                json.dump(out_json, outfile, indent=4, sort_keys=True, default=str)
                outfile.write("]}\n\n\n")
            outfile.close()

            f.close()
            #print(serialNumber)

        except Exception as e:
            print('! Error: unable to parse Info.plist, error = ' + str(e))
            PrintException()




        db_AddressBook_file     =   pathDBOut(conn, OutPath, db_AddressBook)
        db_SMS_file             =   pathDBOut(conn, OutPath, db_SMS)
        db_Calendar_file        =   pathDBOut(conn, OutPath, db_Calendar)
        db_Notes_file           =   pathDBOut(conn, OutPath, db_Notes)
        db_CloudNotes_file      =   pathDBOut(conn, OutPath, db_CloudNotes)
        db_SMS_file             =   pathDBOut(conn, OutPath, db_SMS)
        db_WhatsApp_file        =   pathDBOut(conn, OutPath, db_WhatsApp)


        plist_WiFi_file         =   pathDBOut(conn, OutPath, plist_WiFi)
        bin_cookies_file        =   pathDBOut(conn, OutPath, bin_cookies)

        conn.close()


        return True





#
#
# DumpAddressBook
#
#





def DumpAddressBook(dbPath, outJSON):
    if dbPath == 0:
        return False

    try:
        conn    = sqlite3.connect(dbPath)
        c       = conn.cursor()

        # just to get names
        # we need proper namses to cXPhone, cXEmail, cXSocialProfile, cXURL (X - can differ)
        query   = '''SELECT * FROM ABPersonFullTextSearch_content'''
        c.execute(query)
        names   = list(map(lambda x: x[0], c.description))
        

        phone_field     = names[[names.index(i) for i in names if 'Phone' in i[-5:]][0]]
        email_field     = names[[names.index(i) for i in names if 'Email' in i[-5:]][0]]
        social_field    = names[[names.index(i) for i in names if 'SocialProfile' in i][0]]
        url_field       = names[[names.index(i) for i in names if 'URL' in i[-4:]][0]]
       
        
        query   = '''SELECT ABPerson.ROWID as id,
                                ABPerson.DisplayName,
                                ABPerson.First,
                                ABPerson.Middle,
                                ABPerson.Last,
                                ABPerson.Nickname,
                                ABPerson.Organization,
                                ABPerson.Department,
                                ABPerson.JobTitle,
                                ABPerson.Note,
                                ABPerson.Birthday,
                                ABPersonFullTextSearch_content.%s,
                                ABPersonFullTextSearch_content.%s,
                                ABPersonFullTextSearch_content.%s,
                                ABPersonFullTextSearch_content.%s,
                                datetime(ABPerson.CreationDate+978307200, 'unixepoch', 'localtime') AS creation_date,
                                datetime(ABPerson.ModificationDate+978307200, 'unixepoch', 'localtime') AS modified_date
                            FROM ABPerson INNER JOIN ABPersonFullTextSearch_content ON ABPerson.ROWID = ABPersonFullTextSearch_content.docid
                            ORDER BY ABPerson.ROWID''' % (phone_field, email_field, social_field, url_field)

        c.execute(query)


    except  Exception as err:
        print("! Error: opening address book database " + str(err))
        PrintException()
        return False


    item = {}
    try:
        f_out       =    open(outJSON, 'w')
        db_name = ' \n { \t"addressbook_' + DB_VAR_MARKER + '": [\n'
        f_out.write(db_name)

        res         =    c.fetchall()
        

        for rowid, DisplayName, First, Middle, Last, Nickname, Organization, Department, JobTitle, Note, BirthDay, cPhone, cEmail, cSocialProfile, cURL, CreationDate, ModifiedDate in res:
            
            item    = {         'rowid'                                     :rowid,
                                'DisplayName'                               :DisplayName,
                                'First'                                     :First,
                                'Middle'                                    :Middle, 
                                'Last'                                      :Last, 
                                'Nickname'                                  :Nickname,
                                'Organization'                              :Organization,
                                'Department'                                :Department,
                                'JobTitle'                                  :JobTitle,
                                'Note'                                      :Note, 
                                'BirthDay'                                  :BirthDay,
                                'cPhone'                                    :cPhone, 
                                'cEmail'                                    :cEmail,
                                'cSocialProfile'                            :cSocialProfile, 
                                'cURL'                                      :cURL, 
                                'CreationDate'                              :CreationDate, 
                                'ModifiedDate'                              :ModifiedDate     }

            json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")

       
    except Exception as e:
         print('! Error: unable to dump address book, error = ' + str(e))


    # finish json with empty entry
    for key in item.keys():
        item[key]   =   null
    
    json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
    f_out.write("]}\n\n\n")
    

    #with open(outJSON, 'w') as outfile:
    #    json.dump(c.fetchall(), outfile, default=base64.b64encode)



    # some special cases
    db_name = ' \n { \t"addressbook_mve_' + DB_VAR_MARKER + '": [\n'
    f_out.write(db_name)

    try:
        sql = "SELECT * FROM ABMultiValueEntry" 
        c       = conn.cursor()
        c.execute(sql)
		
        res     = c.fetchall()
        names   = list(map(lambda x: x[0], c.description))
        for row in res:
            item    = {}
            i   =   0
            for n in names:
                item[n] = row[i]
                i   = i + 1
            json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")


        item    =   {}
        for n in names:
            item[n] = null
        
        json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
        f_out.write("]}\n\n\n")



    except Exception as err:
        print("- Warning: trouble getting ABMultiValueEntry " + str(err))
        PrintException()


    db_name = ' \n { \t"addressbook_mv_' + DB_VAR_MARKER + '": [\n'
    f_out.write(db_name)
    try:
        sql = "SELECT * FROM ABMultiValue" 
        c       = conn.cursor()
        c.execute(sql)
	
        res     = c.fetchall()
        names   = list(map(lambda x: x[0], c.description))
        for row in res:
            item    = {}
            i   =   0
            for n in names:
                item[n] = row[i]
                i   = i + 1
            json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")


        item    =   {}
        for n in names:
            item[n] = null
        
        json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
        
        
        f_out.write("]}\n\n\n")



    except Exception as err:
        print("- Warning: trouble getting ABMultiValue " + str(err))
        PrintException()

    print("+ Address book dumped")
    

    f_out.close()
    conn.close()
    return True






#
#
# DumpCalendar
#
#


def DumpCalendar(dbPath, outJSON):
    if dbPath == 0:
        return False

    try:



        conn    = sqlite3.connect(dbPath)
        c       = conn.cursor()


        query   = '''select rowid, location_id, client_location_id, summary, description, start_date, end_date from CalendarItem;'''
        c.execute(query)




        with open(outJSON, 'w') as outfile:
            #json.dump(c.fetchall(), outfile, default=base64.b64encode)


            f_out       =    open(outJSON, 'w')

            db_name     = ' \n { \t"calendar_' + DB_VAR_MARKER + '": [\n'
            f_out.write(db_name)



            rows        =    c.fetchall()
           
            for rowid, location_id, client_location_id, summary, description, start_date, end_date in rows:



                start_date      =   get_date(start_date); 
                end_date        =   get_date(end_date);



                item    = {     'rowid'                                      :rowid,
                                'LocationID'                                 :location_id,
                                'ClientLocationID'                           :client_location_id,
                                'Summary'                                    :summary,
                                'Description'                                :description,
                                'StartDate'                                  :start_date,
                                'EndDate'                                    :end_date
                                }
                               
                json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
                f_out.write(",")
                



    except Exception as err:
        print('! Error: during operating on calendar database, error = ' + str(err))
        PrintException()
        return False

    finally:
        # empty item
        #names   =   list(map(lambda x: x[0], c.description))
            
            
        item_old    =   item
        item        =   {}
        for n in item_old:
            item[n] = null
        
        json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
       
        f_out.write("]}\n\n\n")
        f_out.close()
        
 

    print("+ Calendar dumped")

    conn.close()
    return True






#
#
# DumpNotes
#
#



def DumpNotes(dbPath, outJSON):
    if dbPath == 0:
        return False

    try:
        conn    = sqlite3.connect(dbPath)
        c       = conn.cursor()

        query   = '''select ZCREATIONDATE, ZTITLE, ZSUMMARY, ZCONTENT from ZNOTE, ZNOTEBODY where ZNOTEBODY.Z_PK= ZNOTE.rowid;'''
        c.execute(query)

        with open(outJSON, 'w') as outfile:
            json.dump(c.fetchall(), outfile, default=base64.b64encode)


    except:
        print('! Error: during operating on notes database, notesDB = %s' % dbPath)
        PrintException()
        return False

    print("+ Notes dumped")

    conn.close()
    return True




#
#
# DumpCloudNotes
#
#



def DumpCloudNotes(dbPath, outJSON):
    if dbPath == 0:
        return False

    folderNames     =   []
    folderCodes     =   []

    try:

       
        conn    = sqlite3.connect(dbPath)
        conn.execute('pragma query_only = ON;')
        c       = conn.cursor()


        # Get uuid string required in full id
        c.execute('SELECT z_uuid FROM z_metadata')
        uuid = str(c.fetchone()[0])

        # Get tuples of note title, folder code, modification date, & id#
        c.execute("""SELECT t1.ztitle1,t1.zfolder,t1.zmodificationdate1,
                            t1.z_pk,t1.znotedata,t2.zdata,t2.z_pk
                     FROM ziccloudsyncingobject AS t1
                     INNER JOIN zicnotedata AS t2
                     ON t1.znotedata = t2.z_pk
                     WHERE t1.ztitle1 IS NOT NULL 
                           AND t1.zmarkedfordeletion IS NOT 1""")
        # Get data and check for d[5] because a New Note with no body can trip us up
        dbItems = [d for d in c.fetchall() if d[5]]
   
    
        # Get ordered lists of folder codes and folder names
        # c       = conn.cursor()
        #c.execute("""SELECT z_pk, ztitle2 FROM ziccloudsyncingobject WHERE ztitle2 IS NOT NULL AND zmarkedfordeletion IS NOT 1""")
        c.execute("""SELECT z_pk, ztitle2 FROM ziccloudsyncingobject WHERE ztitle2 IS NOT NULL""")

        res     =   c.fetchall()

       
        

        if res:
            folderCodes, folderNames = zip(*res)
        else:
            print("- Warning: cloud notes seem to be empty (?)")


    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print('! Error: during operating on cloud notes database (%s), error: %s %s ' % (dbPath, exc_tb.tb_lineno, str(e)))
        PrintException()
        return False

    #print(dbPath)
    #print(folderNames)

    items = [{} for d in dbItems]
    gotOneRealNote = False

    #if os.path.exists(outJSON):
    #    os.remove(outJSON)
    
    #print(outJSON)
    f_out = open(outJSON, 'w')

    db_name = ' \n { \t"cloudnotes_' + DB_VAR_MARKER + '": [\n'
    f_out.write(db_name)

    for i, d in enumerate(dbItems):
        try:

 
            if d[1] not in folderCodes:
                print("- Warning: unknown cloudnote directory - index: %d" % d[1])
                folderName = "UNKNOWN"
            else:
                folderName = folderNames[folderCodes.index(d[1])]
            #if folderName == 'Recently Deleted':
            #     continue

            

            body    = extractNoteBody(d[5])
            item    = {         'title': d[0],
                                'arg': 'x-coredata://' + uuid + '/ICNote/p' + str(d[3]),
                                'folderName': folderName,
                                'body': body}

            json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")
            #print(item)

        except Exception as e:
            print("- Error: getting cloud note: %s" % str(e))
            PrintException()


    # finish json
    item = {       'title'         : null,
                    'arg'           : null,
                    'folderName'    : null,
                    'body'          : null}

    
    json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
    
    f_out.write("]}\n")
    f_out.close()



    print("+ Cloud Notes dumped")

    conn.close()
    return True





#
#
# DumpSMS
#
#


def DumpSMS(dbPath, outJSON, SrcAttachmentDir, DestAttachmentDir):
    if dbPath == 0:
        return False


    try:
        conn    = sqlite3.connect(dbPath)
        c       = conn.cursor()

        if os.path.exists(outJSON):
            os.remove(outJSON)



        all_handle_ids = {}
        c.execute("SELECT * FROM 'handle'")

        for row in c:
            rowid   =   row[0]
            id      =   row[1]
            #print("Adding id: %s  rowid: %d" % (id, rowid))

            all_handle_ids[rowid] = id
            




        #query   = '''SELECT rowid, handle_id, is_from_me, date, id, text FROM message, handle WHERE message.handle_id = handle.rowid ORDER by date;'''
        query   = '''SELECT ROWID, text, handle_id, subject, service, account, "date", is_delivered, is_from_me, is_read, is_audio_message FROM message;'''
        c.execute(query)

        res = c.fetchall()
        #print(res)


        f_out       =    open(outJSON, 'w')

        db_name = ' \n { \t"sms_' + DB_VAR_MARKER + '": [\n'
        f_out.write(db_name)


        for rowid, text, handle_id, subject, service, account, datex, is_delivered, is_from_me, is_read, is_audio_message in res:
            datex       =       dateEpoch2001(datex/10e8)
            
            #datex           =       get_date(datex)
            
            # is there any attachment
            attachment_file         =   null
            attachment_type         =   null
            attachment_file_new     =   null 

            #c       = conn.cursor()
            query       =   '''SELECT filename, mime_type FROM attachment WHERE ROWID IS (SELECT attachment_id from message_attachment_join WHERE message_id IS %i)''' % rowid
            c.execute(query)
            res_att     =   c.fetchone()

            if res_att:
                attachment_file     =   res_att[0]
                attachment_type     =   res_att[1]


                # copy attachment
                src_file                =   attachment_file.replace("~", "")
                src_file                =   pathConvert(str(SrcAttachmentDir) + src_file)
                src_file_ext            =   os.path.splitext(src_file)[1]
                
                dest_part               =   hashlib.sha1(str(attachment_file).encode('utf-8')).hexdigest() + src_file_ext
                attachment_file_new     =   pathConvert(os.path.join(str(DestAttachmentDir), dest_part))

                #print(src_file)
                #print(attachment_file_new)

                try:
                    print('+ Copying SMS attachment \"%s\" ' % (attachment_file_new))
                    shutil.copy(src_file, attachment_file_new) 
                except Exception as err:
                    print('! Error: unable to copy SMS attachment \"%s\" to \"%s\", error = %s ' % (src_file, attachment_file_new, str(err)))
                    PrintException()


            sender = "UNKNOWN"
            if handle_id in all_handle_ids:
                sender = all_handle_ids[handle_id]




            item = {
                'rowid'                 :rowid,
                'text'                  :text, 
                'handle_id'             :handle_id,
                'subject'               :subject,
                'service'               :service, 
                'account'               :account,
                'date'                  :datex,
                'is_delivered'          :is_delivered,
                'is_from_me'            :is_from_me,
                'is_read'               :is_read, 
                'is_audio_message'      :is_audio_message,
                'attachment_file'       :attachment_file,
                'attachment_type'       :attachment_type,
                'attachment_file_new'   :attachment_file_new,
                'sender'                :sender
                }



            
            json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")

            #print("Sms from %s body = \"%s\" " % (sender, text))



 


        

        # test
        #with open(outJSON) as json_file:
        #    data = json.load(json_file)
        #    print(data)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print('! Error: during operating on SMS database, error =  %s %s ' % (exc_tb.tb_lineno, str(e)))
        PrintException()
        return False

    finally:
       # finish json with empty entry

        item = {
                'rowid'                 :null,
                'text'                  :null, 
                'handle_id'             :null,
                'subject'               :null,
                'service'               :null,
                'account'               :null,
                'date'                  :null,
                'is_delivered'          :null,
                'is_from_me'            :null,
                'is_read'               :null,
                'is_audio_message'      :null,
                'attachment_file'       :null,
                'attachment_type'       :null,
                'attachment_file_new'   :null,
                'sender'                :null
                }

        json.dump(item, f_out, indent=8, sort_keys=True, default=str) 
        f_out.write("]}\n")
        f_out.close()
 

    print("+ SMS dumped")

    conn.close()
    return True






#
#
# DumpWIFI
#
#



def DumpWIFI(WifiPlistPath, outJSON):
    if WifiPlistPath == 0:
        return False



    try:
        #print(WifiPlistPath)
        

        f_out       =    open(outJSON, 'w')

        db_name = ' \n { \t"wifi_' + DB_VAR_MARKER + '": [\n'
        f_out.write(db_name)

    


        entry = { }
        with open(WifiPlistPath, 'rb') as f:
            info    =   plistlib.load(f)
            info_w  =   info.get('List of known networks')


            i                   =  0
            out                 =  {}
            for child in info_w:
                
                bssid           =   null
                ssid_str        =   null
                strength        =   null
                lastJoined      =   null
                lastAutoJoined  =   null

                
                if ('BSSID'             in child):              bssid               = child['BSSID']
                if ('SSID_STR'          in child):              ssid_str            = child['SSID_STR']
                if ('Strength'          in child):              strength            = child['Strength']
                if ('lastJoined'        in child):              lastJoined          = child['lastJoined']
                if ('lastAutoJoined'    in child):              lastAutoJoined      = child['lastAutoJoined']
               
                
                # should the time be converted?

                entry = { 
                            'bssid'                 : bssid,
                            'ssid_str'              : ssid_str,
                            'strength'              : strength,
                            'lastJoined'            : lastJoined,
                            'lastAutoJoined'        : lastAutoJoined
                    }

                #out[i]  =    entry


                json.dump(entry, f_out, indent=8, sort_keys=True, default=str) 
                f_out.write(",")

                
                i       =   i + 1


            # test dump
            #with open("C:\\backup\\out\\_forensics_report\\dupa2.txt", "w") as json_file:
            #    json.dump(info_w, json_file, indent=8, sort_keys=True, default=str) 

          
            #json.dump(info_w, f_out, indent=8, sort_keys=True, default=str) 







    except Exception as e:

        print('! Error: during operating on WiFi plist' + str(e))
        PrintException()
        return False

    finally:
        # add empty entry  
        entry2 = {}
        for key in entry.keys():
            entry2[key] = null
        #out[i]  =    entry2

        json.dump(entry2, f_out, indent=8, sort_keys=True, default=str) 
        f_out.write("]}\n\n\n")
        f_out.close()



    print("+ Wifi information dumped")


    return True



#
#
#
# DUMP COOKIES
#
#





def DumpCookies(CookiesBinFilePath, outJSON):
    if CookiesBinFilePath == 0:
        return False


    # based on: https://github.com/as0ler/BinaryCookieReader/blob/master/BinaryCookieReader.py

    try:
        cookie_file     =       open(CookiesBinFilePath, 'rb')
    except IOError as e:
	    print('- Error: unable to open cookie file: %s, error = %s' % (FilePath, str(e)))
	    PrintException()
	    return False



    cookies_out         =   {}
    entry               =   {}
    try:
        #print(WifiPlistPath)
 
        file_header     =       cookie_file.read(4)


        if file_header.decode() != 'cook':
            print('- Error: invalid cookie file signature, file = \"%s\", sig = \"%s\" ' % (CookiesBinFilePath, str(file_header)))
            return False


        f_out       =    open(outJSON, 'w')

        db_name     = ' \n { \t"cookies_' + DB_VAR_MARKER + '": [\n'
        f_out.write(db_name)


        pages       =   []
        page_sizes  =   []
        num_pages   =   unpack('>i', cookie_file.read(4))[0] 

    
        for np in range(num_pages):
	        page_sizes.append(unpack('>i', cookie_file.read(4))[0]) 
	
        for ps in page_sizes:
	        pages.append(cookie_file.read(ps))


        k       =   0
        for page in pages:

            cookie          =       ""

            

            #page            =       page.decode('cp437')
            page            =       BytesIO(page)                                     
            page.read(4)                                            
            num_cookies     =       unpack('<i', page.read(4))[0]                
	
            cookie_offsets=[]
            for nc in range(num_cookies):
                cookie_offsets.append(unpack('<i', page.read(4))[0]) 

            page.read(4)




            for offset in cookie_offsets:
                page.seek(offset)                                   
                cookie_size         =   unpack('<i', page.read(4))[0]             
                cookie              =   BytesIO(page.read(cookie_size))              
		
                cookie.read(4)                                      #unknown
		

                cookie_flags_arr    =   ["", "Secure", "Unknown", "Unknown", "HttpOnly", "Secure; HttpOnly", "Unknown"]
                flags               =   unpack('<i',cookie.read(4))[0]                #Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
		        
                cookie_flags        =   cookie_flags_arr[6]
                if flags <= 5:
                    cookie_flags        =   cookie_flags_arr[flags]
                
 
                cookie.read(4)                                      #unknown
		
                url_offset          =      unpack('<i', cookie.read(4))[0]            
                name_offset         =      unpack('<i', cookie.read(4))[0]           
                path_offset         =      unpack('<i', cookie.read(4))[0]           
                value_offset        =      unpack('<i', cookie.read(4))[0]          
                end_of_cookie       =      cookie.read(8)                         
		                        

                expiry_date_epoch   =       unpack('<d',cookie.read(8))[0]                    # Expiry date is in Mac epoch format: Starts from 1/Jan/2001
                expiry_date         =       get_date(expiry_date_epoch)
               
                create_date_epoch   =       unpack('<d',cookie.read(8))[0]
                create_date         =       get_date(create_date_epoch)
 
                cookie.seek(url_offset - 4)                            #fetch domaain value from url offset
                url =   ''
                u   =   cookie.read(1)
                while unpack('<b',u)[0] != 0:
                    url =   url + u.decode()
                    u   =   cookie.read(1)
				
                cookie.seek(name_offset - 4)                           #fetch cookie name from name offset
                name    =   ''
                n       =   cookie.read(1)
                while unpack('<b',n)[0] != 0:
                    name    =   name + n.decode()
                    n       =   cookie.read(1)
				
                cookie.seek(path_offset - 4)                          #fetch cookie path from path offset
                path    =   ''
                pa      =   cookie.read(1)
                while unpack('<b',pa)[0] != 0:
                    path    =   path + pa.decode()
                    pa      =   cookie.read(1)
				
                cookie.seek(value_offset - 4)                         #fetch cookie value from value offset
                value   =   ''
                va      =   cookie.read(1)
                while unpack('<b',va)[0] != 0:
                    value   =   value + va.decode()
                    va      =   cookie.read(1)


                



                #print('Cookie : '+name+'='+value+'; domain='+url+'; path='+path+'; '+'expires='+expiry_date+'; '+cookie_flags)
        
                entry       =   {
                                'Cookie'            : name,
                                'Value'             : value,
                                'Domain'            : url,
                                'Path'              : path,
                                'Expires'           : expiry_date,
                                'CookieFlags'       : cookie_flags                    
                    }

                #cookies_out[k]      =   entry
                #k                   =   k + 1


                json.dump(entry, f_out, indent=8, sort_keys=True, default=str) 
                f_out.write(",")





    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print('! Error: during operating on cookies binary file, error: %s %s ' % (exc_tb.tb_lineno, str(e)))
        PrintException()
        return False

    finally:
         # add empty entry  
        entry2 = {}
        for key in entry.keys():
            entry2[key] = null
    

        #cookies_out[k]  =    entry2
        json.dump(entry2, f_out, indent=8, sort_keys=True, default=str)         
        f_out.write("]}\n\n\n")
        f_out.close()

    print("+ Cookies information dumped")
    return True















#
#
# DumpWHATSAPP
#
#
# based on https://github.com/wiggin15/whatsapp_history/blob/master/whatsapp.py
#


COLORS = ["#f8ff78", "#85d7ff", "cornsilk", "lightpink", "lightgreen", "yellowgreen", "lightgrey", "khaki", "mistyrose"]


COLOR_BG        =   '#e5ddd5'
COLOR_ME        =   '#dcf8c6'   #COLORS[0]
COLOR_SENDER    =   '#ffffff'   #COLORS[1]



TEMPLATEBEGINNING = u"""
<html>
<head>
<title>%s Conversation with %s</title>
<meta charset="utf-8">
<!-- <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet"> -->
<style type="text/css">
* {
    font-family: 'Roboto', sans-serif;
    margin: 0px;
    padding: 0px;
    box-sizing: border-box;
}
.time {
    color: rgba(0,0,0,0.4);
    font-size: 0.6em;
    text-align: right;
    margin-top: -10px;
}

.chat {
    background-color: #e5ddd5;
    #background-image: url(https://s3-us-west-2.amazonaws.com/s.cdpn.io/1089577/background.png);
    width: 100%%;
    padding: 0px 10%%;
    padding-top: 7px;
    overflow-y: auto;
}



.chat-bubble {
    border-radius: 7px;
    box-shadow: 0 2px 2px rgba(0,0,0,0.05);
    padding: 5px 7px;
    width: 350px;
    max-width: 100%%;
    position: relative;
}

.your-mouth {
    width: 0;
    height: 0;
    border-bottom: 10px solid white;
    border-left: 10px solid transparent;
    position: absolute;
    bottom: 10px;
    left: -10px;
}

.my-mouth {
    width: 0;
    height: 0;
    border-bottom: 10px solid #dcf8c6;
    border-right: 10px solid transparent;
    position: absolute;
    bottom: 10px;
    left: 100%%;
}



.you {
    background: #ffffff;
    margin: 0px auto 10px 0px;
}

.me {
    background: #dcf8c6;
    margin: 0px 0px 10px auto;
}

.content {
    margin: 0.5em 0;
    line-height: 120%%;
    font-size: 0.9em;
}


body {
    background-color: %s;
    font-family: "Helvetica Neue", Arial, sans-serif;
}
.main td {
    max-width:90%%;
    padding-left: 10px;
    padding-right: 10px;
    border-bottom: 5px solid #fff;
}
.main td:first-child {
    white-space: nowrap;
    color: #666;
    font-size: 13px;
}
</style>
</head>
<body>

"""

TEMPLATEEND = u"""
</body>
</html>
"""


TEMPLATE_USE_CLASSIC  =   0


TEMPLATE_CLASSIC_START       =   u"""<table class="main" cellpadding="0" cellspacing="0"><tbody>"""
TEMPLATE_CLASSIC_END         =   u"""</tbody></table>"""


ROWTEMPLATE_CLASSIC = u"""<tr style="background-color: %s"><td>%s</td><td>%s</td><td>%s</td></tr>\n"""



TEMPLATE_NEW_START  = u"""<div class="chat">\r\n"""
TEMPLATE_NEW_END    = u"""</div>\r\n"""



ROWTEMPLATE_NEW_SENDER  = u"""<div class='chat-bubble you'><div class='your-mouth'></div><h6>%s</h6><div class='content'>%s</div><div class='time'>%s</div></div>\n"""
ROWTEMPLATE_NEW_ME      = u"""<div class='chat-bubble me'><div class='my-mouth'></div><h6>%s</h6><div class='content'>"%s"</div><div class='time'>%s</div></div>\n"""





cached_members = {}

def WhatsApp_GetGroupMemberName(conn, id):
    """Fetch group member name from cache or database."""
    if id in cached_members:
        return cached_members[id]

    cursor = conn.cursor()
    cursor.execute("SELECT ZCONTACTNAME FROM ZWAGROUPMEMBER WHERE Z_PK=?", (id,))
    cached_members[id] = next(cursor)[0]
    return cached_members[id]

def WhatsApp_GetMediaData(conn, mediaid, cols):
    """Retrieve specified columns of media data from the database."""
    cursor = conn.cursor()
    cursor.execute(f"SELECT {cols} FROM ZWAMEDIAITEM WHERE Z_PK=?", (mediaid,))
    return next(cursor)

def WhatsApp_CopyMediaFile(WhatsApp_DataDIR, WhatsApp_MediaOutDIR, path_in_backup):
    """Copy media file from backup to output directory."""
    search_paths = ["Library", "Message", "Media"]
    for subdir in search_paths:
        source_path = str(Path(WhatsApp_DataDIR, subdir, path_in_backup.lstrip("/")))
        destination_path = str(Path(WhatsApp_MediaOutDIR, os.path.basename(path_in_backup)))

        if os.path.isfile(source_path):
            print(f"Src = {source_path} -- Dest: {destination_path}")
            shutil.copy(source_path, destination_path)
            return source_path

    return "PATH_NOT_FOUND"

def WhatsApp_HandleMedia(conn, WhatsApp_DataDIR, WhatsApp_MediaOutDIR, mtype, mmediaitem):
    """Handle different media types such as image, video, or audio."""
    media_columns = ["ZMEDIALOCALPATH", "ZMEDIALOCALPATH", "ZMEDIALOCALPATH", "ZVCARDNAME", "ZLATITUDE, ZLONGITUDE"]
    columns = media_columns[mtype - 1]

    sanitized_output_dir = WhatsApp_MediaOutDIR.replace("\\\\?\\", "")
    media_base_path = os.path.basename(os.path.normpath(sanitized_output_dir))

    data = WhatsApp_GetMediaData(conn, mmediaitem, columns)
    media_type_str = {1: "image", 2: "video", 3: "audio", 4: "contact", 5: "location"}[mtype]

    if data[0] is None:
        return f"[missing {media_type_str}]"

    data = ", ".join([str(x) for x in data])

    if mtype in [1, 2, 3]:  # Image, video, or audio
        new_media_path = WhatsApp_CopyMediaFile(WhatsApp_DataDIR, WhatsApp_MediaOutDIR, data)
        tag = ["img", "video", "audio"][mtype - 1]
        controls = " controls" if tag in ["audio", "video"] else ""
        return f'<a href="{media_base_path}/{os.path.basename(new_media_path)}"><{tag} src="{media_base_path}/{os.path.basename(new_media_path)}" style="width:200px;"{controls}></a>'

    if mtype == 4 and data.startswith("="):  # Contact vCard
        try:
            data = codecs.decode(data.encode("ascii"), "quopri").decode("utf-8")
        except Exception:
            pass

    return f"[{media_type_str} - {data}]"

def WhatsApp_GetText(conn, row, WhatsApp_DataDIR, WhatsApp_MediaOutDIR):
    """Generate text representation of a WhatsApp message."""
    mfrom, mtext, mdate, mtype, mgroupeventtype, mgroupmember, mmediaitem = row

    if mtype == 0:  # Regular text message
        return mtext

    if mtype == 6:  # Group event
        mgroupmember_name = "you" if mgroupmember is None else WhatsApp_GetGroupMemberName(conn, mgroupmember)
        if mgroupeventtype not in [1, 2, 3, 4]:
            return f"[group event {mgroupeventtype} by {mgroupmember_name}]"

        event_descriptions = {
            1: f"changed the group subject to {mtext}",
            2: "joined",
            3: "left",
            4: "changed the group photo"
        }
        return f"[{mgroupmember_name} {event_descriptions[mgroupeventtype]}]"

    if mtype in [1, 2, 3, 4, 5]:  # Media message
        return WhatsApp_HandleMedia(conn, WhatsApp_DataDIR, WhatsApp_MediaOutDIR, mtype, mmediaitem)

    return f"[message type {mtype}]"

def WhatsApp_GetFrom(conn, is_group, contact_id, contact_name, your_name, row):
    """Determine the sender of the message."""
    mfrom, mtext, mdate, mtype, mgroupeventtype, mgroupmember, mmediaitem = row

    if mfrom != contact_id:
        return f"{contact_name} - {your_name}" if is_group else your_name

    sender_name = contact_name
    if is_group and mgroupmember is not None and mtype != 6:
        sender_name += f" - {WhatsApp_GetGroupMemberName(conn, mgroupmember)}"

    return sender_name







def DumpWhatsApp(dbPath, outJSON, outputDIR):
    if dbPath == 0:
        return False


    entry                           =       {}
    my_name                         =       "me"

    WhatsApp_DataDIR                =       os.path.dirname(dbPath)
    WhatsApp_DataDIR                =       WhatsApp_DataDIR + ("" if WhatsApp_DataDIR.startswith("/") else "/")


    WhatsApp_MediaOutDIR_Name       =       "Media"
    WhatsApp_MediaOutDIR            =       os.path.join(str(outputDIR), WhatsApp_MediaOutDIR_Name)

    if not os.path.isdir(WhatsApp_MediaOutDIR):
        print("+ WhatsApp media directory = \"%s\"" % WhatsApp_MediaOutDIR)
        os.makedirs(WhatsApp_MediaOutDIR)
      
    WhatsApp_MediaOutDIR            =       WhatsApp_MediaOutDIR + SEP
    #print("WhatsApp_MediaOutDIR = " + str(WhatsApp_MediaOutDIR))



    try:
        if os.path.exists(outJSON):
            os.remove(outJSON)

        conn    = sqlite3.connect(dbPath)
        c       = conn.cursor()



        
        f_out       =    open(outJSON, 'w')


        db_name = ' \n { \t"whatsapp_' + DB_VAR_MARKER + '": [\n'
        f_out.write(db_name)





        c.execute('''SELECT COUNT(*) FROM ZWACHATSESSION''')
        num_of_contacts = c.fetchone()[0]
       


        c.execute('''SELECT ZCONTACTJID, ZPARTNERNAME, ZSESSIONTYPE FROM ZWACHATSESSION''')
        row = c.fetchall()
        

        for contact_id, contact_name, is_group in row:
            print("ContactID = %s - is_group=%d" % (contact_id, is_group))

            # process all chat
            query = '''SELECT ZFROMJID, ZTEXT, ZMESSAGEDATE, ZMESSAGETYPE, ZGROUPEVENTTYPE, ZGROUPMEMBER, ZMEDIAITEM FROM ZWAMESSAGE WHERE ZFROMJID='%s' OR ZTOJID='%s';''' % (contact_id, contact_id)
            c.execute(query)


            fname       =   os.path.join(str(outputDIR), sanitize_filename(contact_id) + '.html')


            html        = open(fname, 'w', encoding="utf-8")
            html.write(TEMPLATEBEGINNING % ("WhatsApp", contact_id, COLOR_BG))


            
            if TEMPLATE_USE_CLASSIC  == 1:
                 html.write(TEMPLATE_CLASSIC_START)
            else:
                html.write(TEMPLATE_NEW_START)


            index       =   0
            row2        =   c.fetchall()
            # for every message with this contact

            num_messages    =   0

            for ZFROMJID, ZTEXT, ZMESSAGEDATE, ZMESSAGETYPE, ZGROUPEVENTTYPE, ZGROUPMEMBER, ZMEDIAITEM in row2:
                
                num_messages        =   num_messages + 1
                date                =   get_date(ZMESSAGEDATE)
                body                =   WhatsApp_GetText(conn, row2[index], WhatsApp_DataDIR, WhatsApp_MediaOutDIR)
                sender              =   WhatsApp_GetFrom(conn, is_group, contact_id, contact_name, my_name, row2[index])


                #print("From " + sender)
                #print("Body " + body)

                sender_new      =   sender + " (" + contact_id + ")"

                r_template      =   ROWTEMPLATE_NEW_ME
                color           =   COLOR_ME
                if sender != my_name:
                    color       = COLOR_SENDER
                    sender_new  = sender + " (" + contact_id + ")"
                    r_template  = ROWTEMPLATE_NEW_SENDER


                if TEMPLATE_USE_CLASSIC == 1:
                    html.write((ROWTEMPLATE_CLASSIC % (color, date, sender_new, body)))
                else:
                    html.write(r_template % (sender_new, body, date))


                index       =   index + 1




            
            if TEMPLATE_USE_CLASSIC  == 1:
                 html.write(TEMPLATE_CLASSIC_END)
            else:
                html.write(TEMPLATE_NEW_START)


            html.write(TEMPLATEEND)
            html.close()


            # write json entry about this conversation
            f_size      =   os.path.getsize(fname);

            entry       =   {
                                'ContactID'         : contact_id,
                                'ContactName'       : contact_name,
                                'IsGroup'           : is_group,
                                'Path'              : fname,
                                'NumOfMessages'     : num_messages,
                                'FileSize'          : f_size
                    }

            
            json.dump(entry, f_out, indent=8, sort_keys=True, default=str) 
            f_out.write(",")





    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print('! Error: during operating on WhatsApp DB, error: %s %s ' % (exc_tb.tb_lineno, str(e)))
        PrintException()
        return False

    finally:
        entry       =   {
                                'ContactID'         : null,
                                'ContactName'       : null,
                                'IsGroup'           : null,
                                'Path'              : null,
                                'NumOfMessages'     : null,
                                'FileSize'          : null
                    }

            
        json.dump(entry, f_out, indent=8, sort_keys=True, default=str) 
        f_out.write("]}\n\n\n")
        f_out.close()

    print("+ WhatsApp info dumped")
    return True






def ConvertJSONtoJS(JSON_dirIN, JS_outIN):
    JSON_dirIN      =   pathConvert(JSON_dirIN)
    #JS_outIN        =   pathConvert(JS_outIN)


    #print("JSON_dirIN = " + JSON_dirIN)

    py  = Path(JSON_dirIN).glob("*.json")
    for file in py:
        

        org_fname       =   os.path.basename(file)
        js_path         =   os.path.join(JS_outIN, org_fname + ".js")

        #print("JSON file = " + str(file))
        #print("js path " + js_path)


        #var_name        =   org_fname.replace(".", "_")
        f_out           =   open(js_path, "w")
        #f_out.write("var " + var_name + " = ")
        

        # ]}  - end with ';'
        # _db - start with var
        with open(file) as infile:
            for line in infile:
                full_line = line
                if ']}' in full_line:
                    full_line = full_line.replace("\n", "")
                    full_line = full_line + ' ; \n'

                #print("Line = " + line)
                if DB_VAR_MARKER in line:
                    var_name    =   line[:line.index(DB_VAR_MARKER)].replace('"', '').replace('{', "") + "db"
                    var_name    =   "IR_" + var_name.replace(' ', '').replace("\t", '')

                    #frag        =   line[:line.index(DB_VAR_MARKER)].replace('"', '').replace('{', "")
                    #print('frag = \"%s\"' % frag)
                    
                   
                    full_line   =   full_line.replace("\n", "")
                    full_line   =   full_line.replace(DB_VAR_MARKER, "db")
                    full_line   =   "var " + var_name + " = " + full_line

                    print('VAR = ' + var_name + '   END')
                    #print('full line =' + full_line)
                    #sys.exit(0)

                

                f_out.write(full_line)
        #f_out.write(";")


#
#
# MAIN
#
#

IS_DB_ENCRYPTED     =   False

print("+ iREPAIR FORENSICS BACKUP REPORT GENERATOR\r\n")
print("+ (c) Piotr Bania / piotrbania.com \r\n")



py_ver1     =   sys.version_info[0]
py_ver2     =   sys.version_info[1]


# python 3.8 required, on 3.7 plistlib is broken
if ((py_ver1 != 3) or (py_ver2 < 8)):
    print("- Error: python 3.8 or newer required, current python version: %s.%s" % (py_ver1, py_ver2))
    sys.exit(1)


Password                    =        "???"      # will be only used in case of encrypted backup
ReportPathSheet             =        "sheet.html"
args_set                    =       False


if 'iarg0' in vars() or 'iarg0' in globals():
    print("+ Running forensics script, arg0 = \"%s\", arg1 = \"%s\" " % (iarg0, iarg1))
    print("+ Sheet file: \"%s\"" % iarg2)
    ReportPathSheet         =       iarg2
    args_set = True
    #sys.exit(0)



if (len (sys.argv) != 3) and (args_set == False):
    print("! Usage: python forensics.py <backup_dir> <output_dir> ")
    print("! for example: python forensics.py \"C:\\backup\\ad62541da7307fd9de53eba2039ba9ccf5f3b090\" \"C:\\backup\\out\" ")
    sys.exit(1)


if args_set == False:
    iarg0                           =        sys.argv[1]
    iarg1                           =        sys.argv[2]



print("+ Directory with backup = %s" % iarg0)
print("+ Directory with report = %s" % iarg1)



#iarg0                           =        'C:\\backup\\ad62541da7307fd9de53eba2039ba9ccf5f3b090'
#//iarg0                           =       'C:\\backup\\b489eb38dfd26b6d7f58b6f946c76f75534d16df'
#iarg1                           =        'C:\\backup\\out'

iarg2                           =        pathConvert(os.path.join(iarg1, "_forensics_report"))
iarg3                           =        pathConvert(os.path.join(iarg2, "json"))
JS_out                          =        pathConvert(os.path.join(iarg2, "js"))   

db_AddressBook_out              =        pathConvert(os.path.join(iarg3, "AddressBook.json"))     
db_Calendar_out                 =        pathConvert(os.path.join(iarg3, "Calendar.json"))      
db_Notes_out                    =        pathConvert(os.path.join(iarg3, "Notes.json"))
db_CloudNotes_out               =        pathConvert(os.path.join(iarg3, "CloudNotes.json")) 
db_SMS_out                      =        pathConvert(os.path.join(iarg3, "SMS.json"))

db_WiFi_out                     =        pathConvert(os.path.join(iarg3, "WiFi.json")) 
db_Cookies_out                  =        pathConvert(os.path.join(iarg3, "Cookies.json"))   
db_WhatsApp_out                 =        pathConvert(os.path.join(iarg3, "WhatsApp.json")) 


SrcAttachmentDir                =        pathConvert(os.path.join(iarg1, "MediaDomain"))
DestAttachmentDir               =        pathConvert(os.path.join(iarg2, "attachments")) 
DestWhatsAppDir                 =        pathConvert(os.path.join(iarg2, "WhatsApp_chats")) 


ReportPath                      =        pathConvert(os.path.join(iarg2, "report.html")) 


try:

    make_dirs       =   [iarg2, iarg3, JS_out, DestAttachmentDir, DestWhatsAppDir]
    for xdir in make_dirs:
        xdir    =   str(xdir)
        d       =   pathConvert(xdir)
        if not os.path.isdir(d):
            print("+ Creating directory: " + xdir)
            os.makedirs(d)
        


# copy report sheet
    shutil.copy(ReportPathSheet, ReportPath) 

except Exception as e:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    print("- Error: during creating output dir/files - error: %s" % str(e))



# do the backup

if readBackup(iarg0, iarg1, iarg3, Password) == False:
    print("- Error: unable to read backup, quiting")
    sys.exit(0)


DumpAddressBook(db_AddressBook_file, db_AddressBook_out)
DumpCalendar(db_Calendar_file, db_Calendar_out)
DumpNotes(db_Notes_file, db_Notes_out)
DumpCloudNotes(db_CloudNotes_file, db_CloudNotes_out)
DumpSMS(db_SMS_file, db_SMS_out, SrcAttachmentDir, DestAttachmentDir)

DumpWIFI(plist_WiFi_file, db_WiFi_out)
DumpCookies(bin_cookies_file, db_Cookies_out)
DumpWhatsApp(db_WhatsApp_file, db_WhatsApp_out, DestWhatsAppDir)



ConvertJSONtoJS(iarg3, JS_out)


print("+ All done")