import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
import json
import argparse
from termcolor import colored
import colorama
colorama.init()

settings = {
    'initial_file': 'initial_file.txt',
    'encrypted_file': 'encrypted_file.txt',
    'decrypted_file': 'decrypted_file.txt',
    'symmetric_key': 'symmetric.txt',
    'public_key': 'public.pem',
    'private_key': 'secret.pem',
    'random_value': 'random_value.txt'
}

# пишем в файл
with open('settings.json', 'w') as fp:
    json.dump(settings, fp)
# читаем из файла
with open('settings.json') as json_file:
    json_data = json.load(json_file)

#print(json_data)

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')

args = parser.parse_args()
if args.generation is not None:
    # Генерируем ключи
    print(colored('Выполнять первое задание: ', 'blue'))
    print(colored('1.1. Сгеренировать ключ для симметричного алгоритма.', 'green'))
    # Генерация ключа симметричного алгоритма шифрования 3DES - ключ 64 битов
    key = os.urandom(8)
    print(type(key))
    print(key)

    print(colored('1.2. Сгенерировать ключи для ассиметричного алгоритма.', 'green'))
    # Генерация пары ключей для ассиметричного алгоритма шифрования
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    print('- Закрытый ключ: ')
    print(type(private_key))
    print(private_key)
    print('- Открытый ключ: ')
    print(type(public_key))
    print(public_key)

    print(colored('1.3. Сериализовать ассиметричные ключ.', 'green'))
    # сериализация открытого ключа в файл
    with open(json_data['public_key'], 'wb') as public_file:
        public_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))

    print('Сериализовал открытый ключ в файл ' + json_data['public_key'])

    # сериализация закрытого ключа в файла
    with open(json_data['private_key'], 'wb') as private_file:
        private_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                     encryption_algorithm=serialization.NoEncryption()))
        print('Сериализовал открытый ключ в файл ' + json_data['private_key'])

    print(colored('1.4. Защифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.',
                  'green'))
    # шифрование симметричного ключа при помощи RSA-OAEP
    c_symmetric = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(), label=None))
    with open(json_data['symmetric_key'], 'wb') as symmetric_file:
        symmetric_file.write(c_symmetric)
    print('Сохранил шифрование симметричного влюча в файл ' + json_data['symmetric_key'])

elif args.encryption is not None:
    print(colored("Выполнять второе задание: ", 'blue'))

    print(colored('2.1. Расшифровать симметричный ключ.', 'green'))
    # десериализация открытого ключа
    with open(json_data['public_key'], 'rb') as pem_in:
        public_bytes = pem_in.read()
    d_public_key = load_pem_public_key(public_bytes)
    # десериализация закрытого ключа
    with open(json_data['private_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    # десиариализации симметричного ключа
    with open(json_data['symmetric_key'], 'rb') as symmetric_file:
        c_symmetric_key = symmetric_file.read()

    # дешифрование симметричного ключа асимметричным алгоритмом
    dc_symmetric_key = d_private_key.decrypt(c_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                           algorithm=hashes.SHA256(),
                                                                           label=None))
    print(type(dc_symmetric_key))
    print(dc_symmetric_key)
    print(colored('2.2. Зашифровать текст симметричным алгоритмом и сохранить по указанному пути.', 'green'))
    # десиариализации текста из текстового файла
    with open(json_data['initial_file'], 'r', encoding='utf-8') as file_text:
        text = file_text.read()
    text = bytes(text, 'UTF-8')

    # шифрование текста симметричным алгоритмом

    # паддинг данных для работы блочного шифра - делаем длину сообщения кратной длине шифркуемого блока
    from cryptography.hazmat.primitives import padding

    padder = padding.ANSIX923(1024).padder()
    padded_text = padder.update(text) + padder.finalize()

    # шифрование текста симметричным алгоритмом
    iv = os.urandom(8)  # случайное значение для инициализации блочного режима, должно быть размером с блок и
    # каждый раз новым
    # cохранить случайное значение в файл
    with open(json_data['random_value'], 'wb') as file_value:
        file_value.write(iv)
    cipher = Cipher(algorithms.TripleDES(dc_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    with open(json_data['encrypted_file'], 'wb') as enc_file:
        enc_file.write(c_text)
    print('Шифрованный текст сохранился в файл: ' + json_data['encrypted_file'])

else:
    print(colored('Выполнять третье задание: ', 'blue'))
    print(colored('3.1. Расшифровать симметричный ключ.', 'green'))
    # Десериализация открытого ключа
    with open(json_data['public_key'], 'rb') as pem_in:
        public_bytes = pem_in.read()
    d_public_key = load_pem_public_key(public_bytes)

    # Десериализация открытого ключа
    with open(json_data['private_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None)

    # Десиариализации симметричного ключа
    with open(json_data['symmetric_key'], 'rb') as symmetric_file:
        c_symmetric_key = symmetric_file.read()

    # Дешифрование симметричного ключа ассимтеричным алгоритмом
    dc_symmetric_key = d_private_key.decrypt(c_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                           algorithm=hashes.SHA256(), label=None))
    print(type(dc_symmetric_key))
    print(dc_symmetric_key)

    print(colored('3.2. Расшифровать текст симметричным алгоритмом и сохранить по указанному пути.', 'green'))

    # Десиариализации шифрованого текста из файла
    with open(json_data['encrypted_file'], 'rb') as en_file:
        c_text = en_file.read()

    # Десиариализации случайного значения iv
    with open(json_data['random_value'], 'rb') as file_value:
        iv = file_value.read()

    # Дешифрование и депаддинг текста симметричным алгоритмом
    cipher = Cipher(algorithms.TripleDES(dc_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(c_text) + decryptor.finalize()
    from cryptography.hazmat.primitives import padding
    unpadder = padding.ANSIX923(1024).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    decode_text = unpadded_dc_text.decode('UTF-8')
    with open(json_data['decrypted_file'], 'w') as dec_file:
        dec_file.write(decode_text)
    print('Расшифрованный текст сохранился в файл: ' + json_data['decrypted_file'])
