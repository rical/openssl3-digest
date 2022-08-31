# About

Example of how to calculate various hash values of a file using OpenSSL 3.0.

# Usage Example

```
$ make
gcc -Wall    digest.c  -lssl -lcrypto -o digest

$ ./digest data
md5    : 71e979387e8c76b3862014dae960e618
sha1   : 45cdbc950d688bc0462918aa8ef8e8a61ce04cb9
sha256 : ca434309e60046efbdc68c4a39443b34050cac45186e67692a4f10b1f11ea684
sha512 : 67e32fcf849735449d34a8685ad81b97269f22901cdd0aef44b3e733701ceb47119437d0cf6795f06da6902c444cf3e5fa1d3bb7d378106dc383246217f33a46
```
