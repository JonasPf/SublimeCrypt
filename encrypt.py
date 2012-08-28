"""
Copyright (c) 2012, Jonas Pfannschmidt
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
import sublime, sublime_plugin
import base64
from encrypt_helper import AESHelper

PREFIX = "SublimeCrypt~01!"
PREFIX_LEN = len(PREFIX)

class BaseCryptFile(sublime_plugin.TextCommand):
    def run(self, edit):
        self._edit = edit
        self.view.window().show_input_panel("Enter password:", "", self.on_entered_password, None, None)

    def on_entered_password(self, password):
        raise NotImplementedError

    def is_encrypted(self):
        prefix_region = sublime.Region(0, PREFIX_LEN)
        text = self.view.substr(prefix_region)
        return text == PREFIX

    def get_all_text(self):
        all_region = sublime.Region(0, self.view.size())
        unicode_text = self.view.substr(all_region)
        text = unicode_text.encode('utf8') 
         
        return text   

    def replace_all_text(self, text):
        unicode_text = text.decode('utf8')
        all_region = sublime.Region(0, self.view.size())
        self.view.replace(self._edit, all_region, unicode_text)          


class EncryptFile(BaseCryptFile):
    def on_entered_password(self, password):
        text = self.get_all_text()

        # Encrypt
        helper = AESHelper()
        cipher = helper.encrypt_string(text, password)

        # Convert to base64 to display the bytes in the editor.
        # The prefix may be used to later decide whether the file was encrypted.
        cipher = PREFIX + base64.b64encode(cipher)

        self.replace_all_text(cipher)
        sublime.status_message("Encrypted") 

    def is_visible(self):
        return not self.is_encrypted()

class DecryptFile(BaseCryptFile):
    def on_entered_password(self, password):
        cipher = self.get_all_text()

        # Prepare text
        cipher = cipher[PREFIX_LEN:]
        cipher = base64.b64decode(cipher)

        # Decrypt
        helper = AESHelper()
        text = helper.decrypt_string(cipher, password)

        if (text):
            self.replace_all_text(text)
            sublime.status_message("Decrypted") 
        else:
            sublime.status_message("Wrong password")

    def is_visible(self):
        return self.is_encrypted()

