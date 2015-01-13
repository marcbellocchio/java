# java
java code of json secure file, the objective is to insert data in a json file, such data is encrypted using a specific cryptographic cascade of symetrical algorithn.

features :
- read and write a json file
- encrypt decrypt using twofish cbc
- hash data using Whirlpool-T version
- encrypt decrypt using cascade (twofish serpent) block size is 128 bit, key is 256 bit.
- wipe data using a specific algorithm "anubis", block size is 128 bit, random key of 128 to 320 bit
