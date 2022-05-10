# Openssl encrypted file by aes-256-cbc and pbdkf2

## Installation

Install dependencies library by the command in terminal:
```bash
sudo apt install openssl libssl-dev
```

## Usage

### Compile code by command

- With `Make`

```bash
g++ -o app openssl_encrypt_pbdfk2.cpp -L/usr/local/lib/ -lssl -lcrypto
```

- With CMake

```bash
cd build
cmake ..
make
ln -sf ../ngoc.jpg
```

### Run encrypt file by command

```bash
./app enc ./ngoc.jpg ./ngoc.enc ando286 28062002
```

### Opessl CLI to encrypt file.

- You can try to encrypt file by openssl CLI and use my program to decode.

```bash
openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 28062002 -k ando286 -in ./ngoc.jpg -out ./ngoc_2.enc
```

### Run decrypt file by command

```bash
./app dec ./ngoc.enc ./ngoc_dec.jpg ando286 28062002
./app dec ./ngoc_2.enc ./ngoc_dec2.jpg ando286 28062002
```

