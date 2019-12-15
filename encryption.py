import argparse
import tkinter.scrolledtext as st
from tkinter import Tk, Button, END, RAISED, X

from cryptography.fernet import Fernet as frt

font_regular="google sans regular"
font_bold="google sans bold"

encrypt_data_get = None
decrypt_data_get = None

key = b"DhQuyqPEot6MEyE3qad2iHSL5KV1V0LqPw-9ncnbxp0="

def encryptor(words):
    def cipher(words):
        result_cipher = '' # cipher text is stored in this variable
        i = len(words) - 1
        while i >= 0:
            result_cipher = result_cipher + words[i]
            i = i - 1
        return result_cipher
    def fernet_en(words):
        f=frt(key)
        result_fernet = f.encrypt(words.encode('utf-8')) # need to convert the string to bytes
        return result_fernet.decode("utf-8")
    def trans_en(words):
        decrypted = b'!@M[#Na]Bb{V\}C|;X`cZ32L1,Kd:J."H</Ge$F%^Df>S?6A54PghOi Ij&U*9Y8~T7(RklEm+WnoQ0)pqrs=tu_vwx-yz'
        encrypted = b"qwer{t1/.},#@!| 23y~':;\uioM^%$]N<[pB45V>C6XasZ(?L*&Kd=JfgH78G9)FhDjSkA+lP`OzIU0_YxTcRvE-WbQnm"
        encrypt_table = bytes.maketrans(decrypted, encrypted)
        result_trans_en = words.translate(encrypt_table)
        return result_trans_en
    result_encryption=trans_en(cipher(fernet_en(cipher(trans_en(cipher(fernet_en(trans_en(words))))))))
    return result_encryption


def decryptor(words):
    def cipher(words):
        result_cipher = '' #cipher text is stored in this variable
        i = len(words) - 1
        while i >= 0:
            result_cipher = result_cipher + words[i]
            i = i - 1
        return result_cipher
    def fernet_de(words):
        f=frt(key)
        result_fernet = f.decrypt(words.encode('utf-8')) #need to convert the string to bytes
        return result_fernet.decode("utf-8")
    def trans_de(words):
        decrypted = b'!@M[#Na]Bb{V\}C|;X`cZ32L1,Kd:J."H</Ge$F%^Df>S?6A54PghOi Ij&U*9Y8~T7(RklEm+WnoQ0)pqrs=tu_vwx-yz'
        encrypted = b"qwer{t1/.},#@!| 23y~':;\uioM^%$]N<[pB45V>C6XasZ(?L*&Kd=JfgH78G9)FhDjSkA+lP`OzIU0_YxTcRvE-WbQnm"
        decrypt_table = bytes.maketrans(encrypted, decrypted)
        result_trans_de = words.translate(decrypt_table)
        return result_trans_de
    result_encryption=trans_de(fernet_de(cipher(trans_de(cipher(fernet_de(cipher(trans_de(words))))))))
    return result_encryption


def encrypt():
    data=encrypt_data_get.get('1.0',END+'-1c')
    encrypted_data=encryptor(data)
    decrypt_data_get.insert("1.0",encrypted_data)


def decrypt():
    data=decrypt_data_get.get('1.0',END+'-1c')
    decrypted_data=decryptor(data)
    encrypt_data_get.insert("1.0",decrypted_data)


def graphical():
    main=Tk()
    main.title("Encrption <--> Decryption")
    main.geometry("570x500")
    main.resizable(0,0)
    main.maxsize(height=500,width=570)
    # main.iconbitmap(r'Versions\encryption_icon.ico')

    Button(text="Encrypt",bg="white",fg="green",font=(font_bold,26),command=encrypt).pack(fill=X)
    encrypt_data_get=st.ScrolledText(main,width=50,height=8,bg="white",fg="black",font=(font_regular,13),relief=RAISED,bd=3)
    encrypt_data_get.pack()

    Button(text="Decrypt",bg="white",fg="red",font=(font_bold,26),command=decrypt).pack(fill=X)
    decrypt_data_get=st.ScrolledText(main,width=50,height=8,bg="white",fg="black",font=(font_regular,13),relief=RAISED,bd=3)
    decrypt_data_get.pack()

    main.mainloop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", help="Encrypt", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt", action="store_true")
    parser.add_argument("-g", "--graphical", help="Opens graphical window", action="store_true")
    parser.add_argument("-k", "--key", help="Key of encryption", action="store_true")

    args = parser.parse_args()

    if args.graphical:
        graphical()
    else:
        if args.encrypt:
            value = input("Value: ")
            try:
                print(f"\nEncrypted: {encryptor(value)}")
            except Exception:
                print("Some error occured!")
        
        if args.decrypt:
            value = input("Value: ")
            keyInp = input("Key(?): ")
            global key
            key = keyInp if keyInp else key

            try:
                print(f"\nDecrypted: {decryptor(value)}")
            except Exception:
                print("\n=> Some error occured! It might be a key or value problem! <=")

        if args.key:
            print(f"Key: {key}")


main()
