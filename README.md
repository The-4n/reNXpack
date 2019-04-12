# reNXpack

![License](https://img.shields.io/badge/license-ISC-blue.svg)

reNXpack is a tool for repacking Nintendo Switch nsps to work on lower firmwares  

reNXpack is based on [hactool](https://github.com/SciresM/hactool) by SciresM  
Thanks: SciresM, Rajkosto, Switch Brew  

## Features

* Repack games, updates and dlcs with lowest encryption keys
* Convert titlekey encrypted ncas to standard encrypted ncas
* Patch required firmware version and required application version to zero
* Support nsps containing multiple games, updates and dlcs
* Multiplatform compatibility including Windows, macOS and Linux

## Usage

You should load your keyset file with -k or --keyset option followed by a path to it or place your keyset file with "keys.dat" filename in the same folder as reNXpack  
Required keys are:  

Key Name | Description
-------- | -----------
header_key | NCA Header Key
key_area_key_application_xx | Application key area encryption keys
titlekek_xx | Title key encryption keys

By default, Created nsp files are located in the same folder as reNXpack with 'titleid_reNXpack.nsp' filename  
You can change output directory with -o, --outdir option  
reNXpack creates "renxpack_extracted_nsp" folder as a temp directory, It deletes the directory content before and after conversion  
If you use -t, --tempdir option to choose a temporary directory, Make sure it's an empty directory and it's not the same as output directory otherwise reNXpack deletes it  

```
*nix: ./renxpack [options...] <path_to_file.nsp>  
Windows: .\renxpack.exe [options...] <path_to_file.nsp>  
  
Options:  
-k, --keyset             Set keyset filepath, default filepath is ./keys.dat  
-h, --help               Display usage  
-t, --tempdir            Set temporary directory path  
-o, --outdir             Set output directory path  
```

## Licensing

This software is licensed under the terms of the ISC License.  
You can find a copy of the license in the LICENSE file.
