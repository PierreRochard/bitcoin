## Example:
## $ python check_for_privkeys.py --berkeley_env_directory /Volumes/Mac\ Storage/bitcoin-mainnet/regtest/wallets/

import binascii
import os
import array


def main(berkeley_env_directory, unencrypted_wallet_name):
    header = [0xd6, 0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x20]
    header_ptr = 0
    privkeys = []
    unencrypted_wallet_path = os.path.join(berkeley_env_directory, unencrypted_wallet_name)
    with open(unencrypted_wallet_path, 'rb') as f:
        read_bytes = f.read()
        in_privkey = False
        cur_privkey = []
        print('Reading 1024 bytes at a time')
        for b in read_bytes:
            if in_privkey and len(cur_privkey) < 32:
                cur_privkey.append(b)
                continue
            elif len(cur_privkey) == 32:
                pk = array.array('B', cur_privkey).tostring()
                privkeys.append(pk)
                print('Found a private key ' + str(len(privkeys)))
                cur_privkey.clear()
                in_privkey = False
                continue
            if b == header[header_ptr]:
                header_ptr += 1
                if header_ptr == len(header):
                    # We're now at a private key
                    in_privkey = True
                    header_ptr = 0
            else:
                header_ptr = 0

    print('Checking log files now')
    database_logs_directory = os.path.join(berkeley_env_directory, 'database')
    for filename in os.listdir(database_logs_directory):
        file_path = os.path.join(database_logs_directory, filename)
        with open(file_path, 'rb') as f:
            privkey_found = []
            read_bytes = f.read()
            for privkey in privkeys:
                if privkey in read_bytes:
                    privkey_found.append(str(binascii.hexlify(privkey)))
            print('Found', len(privkey_found), 'private keys in', file_path)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--berkeley_env_directory', dest='berkeley_env_directory')
    parser.add_argument('--unencrypted_wallet_name', dest='unencrypted_wallet_name', default='wallet.dat')
    args = parser.parse_args()
    main(os.path.abspath(args.berkeley_env_directory), args.unencrypted_wallet_name)
