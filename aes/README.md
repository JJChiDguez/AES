# AES C-implementation


  Created by:	Jesús Javier Chi Domínguez 
               <chidoys@gmail.com>,
               <jjchi@computacion.cs.cinvestav.mx>
               
#################################################

Building the executable files:

	gcc aes_encrypt.c -o encrypt
	gcc aes_decrypt.c -o decrypt
	
#################################################

File texts:

	You should to write the 
	initial key in the 
	initial_key.txt

	If you want to encrypt:	
	You should to write the 
	plain text in the 
	initial_text.txt

	If you want to decrypt:
	You should to write the 
	cipher text in the 
	initial_text_cipher.txt

Format text:

	In all file text you should 
	write the required data as
	follows
	 
	XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX

	where X denotes a hexadecimal 
	value. For example:

	69c4e0d8 6a7b0430 d8cdb780 70b4c55a


#################################################

The output of aes_encrypt will be saved in 
the file initial_text_cipher.txt.

The output of aes_decrypt will be saved in 
the file initial_text.txt.

#################################################

To compile:

	Encrypt: ./encrypt and follow the
	intsructions that appear.

	Decrypt: ./decrypt and follow the
	intsructions that appear.
