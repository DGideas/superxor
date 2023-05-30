# superxor
superXOR tool. Release under WTFPL license. That is, You just DO WHAT THE FUCK YOU WANT TO!

## Usage
This tool can be used for a variety of purposes. It depends on which mode you choose.
### Bit reverse mode(`rev`)
To obtain the bit-reversed file from the original file, use the following command. This mode is the default and does not require any additional configuration.
```bash
python3 superxor.py original.file -o reversed.file
```

To reverse the bit-reversed file back to the original file, simply use:

```bash
python3 superxor.py reversed.file -o original.file
```

You can also perform this operation with a whole dictionary:

```bash
pytho3n superxor.py from_dictionary --to to_dictionary
```


The `-r` flag is not applicable in bit reverse mode.

### SHA256 Key rotate encrypt mode(`key256`)
In this mode, you can encrypt a file using a provided key string. It is crucial to keep your key safe, as losing it will result in permanent data loss. To encrypt your files, use the following command:
```bash
python3 superxor.py original.file -o encrypted.file -m key256 -k YOUR_KEY_HERE
```

To decrypt the encrypted file, use the following command:

```bash
python3 superxor.py encrypted.file -o original.file -m key256 -k YOUR_KEY_HERE -r
```

Please note that the `-r` flag is important and should be used when decrypting the file. The security of this encryption method relies on the complexity and strength of the key you choose. It is important to use a strong and unique key to enhance the security of your encrypted files.