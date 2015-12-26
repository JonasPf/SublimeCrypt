# This project is abandoned. Use at your own risk!

Summary
=======

SublimeCrypt is a plugin for Sublime Text 2 to encrypt and decrypt a file, similar to the encryption in Vim. The algorithm used is AES (uses http://caller9.com/blog/tagsearch/aespython/ under the hood).

__Important:__ Always backup an unencrypted version of the file to some safe place. Don't blame me if you lose your data! I have no idea whether this encryption is safe. Also, I don't know if Sublime Text 2 stores parts of the unencrypted 
text somewhere else (e.g. in some cache file). For highly confidential stuff I would always prefer a proven and mature 
encryption solution over this little plugin.

Install
=======

Copy this repository into the Sublime Text 2 "Packages" directory.

Usage
=====

Use the command "Encrypt file" from the Command Palette or click on File -> Encrypt File to encrypt a file. Enter a new password in the input box at the bottom and save the encrypted file. Don't modify the encrypted file or you won't be able to decrypt it again.

Use the command "Decrypt file" from the Command Palette or click on File -> Decrypt File to decrypt a file. Enter the password in the input box at the bottom. If you modify the file, remember to encrypt it again before saving.

To Do
=====

-   Mask password with * instead of showing the plain text
-   Decrypt automatically when opening an encrypted file
-   Encrypt automatically when saving a previously encrypted file

License
=======

Copyright (c) 2012, Jonas Pfannschmidt

Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
