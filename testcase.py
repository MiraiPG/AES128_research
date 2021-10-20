import unittest
from aes import AES
import os
import string
import random
import csv


class Test_aes_ecb(unittest.TestCase):


    # AES ECB Mode Testing for hex string.
    def test_hex(self):
        # Test vector 128-bit key
        key_list= ['000102030405060708090a0b0c0d0e0f','100102030405060708090a0b0c0d0e0f','200102030405060708090a0b0c0d0e0f']
        # Aes mode of operation
        aes = AES(mode='ecb', input_type='hex')
        number = 100000
        for i in range(number):
            #ランダムの数字を生成
            rand_num = random.randint(0,340282366920938463463374607431768211456)
            rand_hex = format(rand_num,'x').zfill(32)
            for keynum in range(3):
                # Encrypt data with your key
                cyphertext = aes.encryption(rand_hex, key_list[keynum])
                # Decrypt data with the same key
                plaintext = aes.decryption(cyphertext, key_list[keynum])
                plaintext_bin = ((bin(int(plaintext,base=16))).lstrip('0b')).zfill(128)
                cyphertext_bin = ((bin(int(cyphertext,base=16))).lstrip('0b')).zfill(128)
                #print(plaintext_bin)
                #平文の上位8bitを出力([]の中身を変更すると抜き取る位を変更できる)
                plaintext_bin_selected = (plaintext_bin[0:8])
                #print(plaintext_bin_selected)
                #暗号文の上位8bitを出力([]の中身を変更すると抜き取る位を変更できる)
                cyphertext_bin_selected = (cyphertext_bin[0:8])
                #print(cyphertext_bin_selected)
                #csvファイルにデータの書き込み
                data = [plaintext_bin_selected,cyphertext_bin_selected]
                f = open('data.csv','a')
                writer = csv.writer(f)
                writer.writerow(data)
                f.close()

                

    '''
    # AES ECB Mode Testing for ascii string.
    def test_str(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Ascii string test
        aes = AES(mode='ecb', input_type='text')
        # 平文をランダムに作成
        number_of_strings = 10
        length_of_string = 4
        for x in range(number_of_strings):
            Root = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length_of_string))
            # Encrypt data with your key
            cyphertext = aes.encryption(Root, key)
            # Decrypt data with the same key
            plaintext = aes.decryption(cyphertext, key)
            # Ensure that data is equal to plaintext
            #self.assertEqual('root', plaintext)
            print(Root)
            print(cyphertext)
    '''
'''
    # AES ECB Mode Testing for raw data.
    def test_data(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Data stream test
        aes = AES(mode='ecb', input_type='data')
        # Random data to encrypt
        data = os.urandom(64)
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)
'''

'''
class Test_aes_cbc(unittest.TestCase):
    # AES CBC Mode Testing for hex string.
    def test_hex(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Data stream test
        aes = AES(mode='cbc', input_type='hex', iv='000102030405060708090A0B0C0D0E0F')
        # Random data to encrypt
        data = ['6bc1bee22e409f96e93d7e117393172a']
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)

    # AES CBC Mode Testing for raw data.
    def test_data(self):
        # Test vector 128-bit key
        key = '000102030405060708090a0b0c0d0e0f'
        # Raw data stream test
        aes = AES(mode='cbc', input_type='data', iv='000102030405060708090A0B0C0D0E0F')
        # Random data to encrypt
        data = os.urandom(254)
        # Encrypt data with your key
        cyphertext = aes.encryption(data, key)
        # Decrypt data with the same key
        plaintext = aes.decryption(cyphertext, key)
        # Ensure that data is equal to plaintext
        self.assertEqual(data, plaintext)

'''

if __name__ == '__main__':
    unittest.TestProgram()
