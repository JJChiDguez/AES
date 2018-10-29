/* Jesus Javier Chi Domi'nguez
 * Centro de Investigacio'n y Estudios Avanzados del Instituto Polite'cnico Nacional, Unidad Zacatenco
 * Departamente de Computacio'n. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// We construct the S-box
// If we want to use AES-128 the values of nk and nr are the followings, if not then we need to change the values.
// nr = 4*( (nk+6) + 1)
int i, j, h;//, nk = 6, nr = 4*( (6+6) + 1);
uint32_t text_initial[4], block[4], Sbox_block[4], key[4], key_initial[4];
int Sbox[16][16] = { {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
   					 {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
 		 			 {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
 		 			 {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
 		 			 {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
 		    		 {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
 		 			 {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		    		 {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		 			 {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		 			 {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		 			 {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
			 		 {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
			 		 {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
			 		 {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
			 		 {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
			 		 {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

// Initial is a function that compute the transpose of a state.
void initial(uint32_t y[4])
{
	int i, j;
	uint32_t x[4];
	for (i = 0; i < 4; ++i) x[i] = 0x0;

	for(i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; ++j)
		{
			x[i] |= ( (y[j] & (0xff000000 >> 8*i)) << 8*i) >> 8*j;
		}
	}
	for (i = 0; i < 4; ++i) y[i] = x[i];
}
// We make the implementation of Sub-bytes function.
void sub_bytes(uint32_t y[4])
{
	int i, j;
	uint32_t x[4];
	for (i = 0; i < 4; ++i) x[i] = 0x0;
	for(i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; ++j)
		{
			x[i] |= (s_box((y[i] & (0xff000000 >> 8*j) ) >> 8*(3-j) ) ) <<  8*(3-j);
		}
	}
	for (i = 0; i < 4; ++i) y[i] = x[i];
}
// We make the implementation of Shift-Rows.
void shift_rows(uint32_t x[4])
{
	int i;
	uint32_t aux_1, aux_2;
	uint32_t aux[3];
	aux[0] = 0xff000000;
	aux[1] = 0xffff0000;
	aux[2] = 0xffffff00;
	for(i = 1; i < 4; i++)
	{
		aux_1 = (aux[i-1] & x[i]) >> 8*(4-i);
		aux_2 = x[i] << 8*i;
		x[i] = aux_1 | aux_2;
	}
}
// dot_x is a function that compute x*z[x] in the GF(2^8).
uint32_t dot_x(uint32_t z)
{
	if ( !(z & 0x80))  return (z << 1) & 0xff;
	else return ( (z << 1) & 0xff ) ^ 0x1b;
}
// ndot is a function that compute (x^n)*z[x] in the GF(2^8).
uint32_t ndot_x(uint32_t x, int n)
{
	int i;
	uint32_t y = x;
	for(i = 0; i < n; i++) y = dot_x(y);
	return y;
}
// dot is a function that compute z[x]*y[x] in the GF(2^8).
uint32_t dot(uint32_t x, uint32_t y)
{
	int i;
	uint32_t z;
	if (y & 0x1) z = x;
	else z = 0;
	for (i = 1; i < 8; ++i)
	{
		if( y & ( 0x01 << i) ) z ^= ndot_x(x, i);
	}
	return z;
}
// We make the implementation of Mix-Columns.
void mix_columns(uint32_t x[4])
{
	int i, j;
	uint32_t y[4], x1, x2, x3, x4, y1, y2, y3, y4;
	for (i = 0; i < 4; ++i) y[i] = 0x0;
	
	for (i = 0; i < 4; ++i)
	{
		x1 = ( x[0] & (0xff000000 >> 8*i) ) >> 8*(3-i);
		x2 = ( x[1] & (0xff000000 >> 8*i) ) >> 8*(3-i);
		x3 = ( x[2] & (0xff000000 >> 8*i) ) >> 8*(3-i);
		x4 = ( x[3] & (0xff000000 >> 8*i) ) >> 8*(3-i);
		y[0] |= (dot(x1, 0x2) ^ dot(x2, 0x3) ^ dot(x3, 0x1) ^ dot(x4, 0x1) ) << 8*(3-i);
		y[1] |= (dot(x1, 0x1) ^ dot(x2, 0x2) ^ dot(x3, 0x3) ^ dot(x4, 0x1) ) << 8*(3-i);
		y[2] |= (dot(x1, 0x1) ^ dot(x2, 0x1) ^ dot(x3, 0x2) ^ dot(x4, 0x3) ) << 8*(3-i);
		y[3] |= (dot(x1, 0x3) ^ dot(x2, 0x1) ^ dot(x3, 0x1) ^ dot(x4, 0x2) ) << 8*(3-i);
	}
	for (i = 0; i < 4; ++i) x[i] = y[i];
}
// We make the implentation of s-box(x).
int s_box(uint32_t x)
{
	return Sbox[(0xf0 & x) >> 4][(0x0f & x)];
}
// We make the implementation of SubWord.
uint32_t SubWord(uint32_t x)
{
	int i;
	uint32_t y = 0x0;
	for(i = 0; i < 4; i++)
	{
		y |= (s_box(  (x & (0xff000000 >> 8*i)) >> 8*(3-i) )) << 8*(3-i);
	}
	return y;
}
// We make the implementation of RotWord.
uint32_t RotWord(uint32_t x)
{
	uint32_t y = 0x0;
	y = (x & 0xff000000) >> 24;
	y |= (x << 8);
	return y;
}
// We make the implementation of Key-Expansion.
void key_expansion(uint32_t* key_i, uint32_t* word, int nk)
{
	int i;
	uint32_t temp;
	for (i = 0; i < nk; ++i)
	{
		word[i] = key_i[i];
	}
	for(i = nk; i < 4*((nk+6) + 1); i++)
	{
		temp = word[i-1];
		if( (i % nk) == 0) {
			temp = SubWord(RotWord(temp)) ^ (ndot_x(1, (i/nk) - 1) << 24);
		}
		else if( (nk > 6) && ( (i % nk) == 4) ) {
			temp = SubWord(temp);
		}
		word[i] = word[i-nk] ^ temp;
	}
}
// We make the implementation of Add-Round-Key.
void add_round_key(uint32_t text[4], uint32_t* word, int round)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		text[i] ^= word[4*round + i];
	}
}
// We start we the algorithm AES
int main()
{
	int nk = 0;
	uint32_t text_initial[4];
	FILE *leer;
	leer = fopen("initial_key.txt","r");
	char nombre[8];
	if( leer == NULL ){
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
	}
	while( fscanf(leer, "%s", nombre)  != EOF ) // reading file..
		nk += 1;
   	if ( nk != 4 && nk != 6 && nk != 8)
	{
		printf("\n Invalid key, the length of the key should be: 128, 192 or 256 bits\n");
		return 0;
	}
	printf("\nAES-%d implementation -> encryption\n", nk*32);
    int nr = 4*( (nk + 6) + 1);
    uint32_t words[4*( (nk + 6)+ 1)], keyS[nk];
    fclose ( leer );
    ////////
	leer = fopen("initial_text.txt","r");
     
    // We obtain of initial_text.txt the plain text to encrypt.
    uint32_t u[4];
    int length;
    for (i = 0; i < 4; ++i) u[i] = 0x00000000;
    for (j = 0; j < 4; ++j)
    {
    	fscanf(leer,"%s",nombre);
    	for(i=0; nombre[i]!='\0'; ++i);
    	length = i;
  		for (i = 0; i < length; ++i)
    	{
    		if ((nombre[i] - '0') < 10) u[j] |= (nombre[i] -'0');
    		else u[j] |= ( (nombre[i] -'0') - 39);
    		if (i < (length - 1) ) u[j] = u[j] << 4;
    	}
	}
	fclose ( leer );
	// We obtain of initial_key.txt the the key used to encrypt.
	leer = fopen("initial_key.txt","r");
	uint32_t v[nk];
	for (i = 0; i < nk; ++i) v[i] = 0x0;
    for (j = 0; j < nk; ++j)
    {
    	fscanf(leer,"%s",nombre);
    	for(i=0; nombre[i]!='\0'; ++i);
    	length = i;
  		for (i = 0; i < length; ++i)
    	{
    		if ((nombre[i] - '0') < 10) v[j] |= (nombre[i] -'0');
    		else v[j] |= ( (nombre[i] -'0') - 39);
    		if (i < (length - 1) ) v[j] = v[j] << 4;
    	}
	}
	fclose ( leer );
	// words is used in the key-expansion.
	for (i = 0; i < 4*( (nk + 6) + 1); ++i)
	{
		words[i] = 0x0;
	}
	// We print the plai text and the key.
	for (i = 0; i < 4; ++i) text_initial[i] = u[i];
	for (i = 0; i < nk; ++i) keyS[i] = v[i];
	printf("\nPlain Text: ");
	for (i = 0; i < 4; i++) printf("%0x ", text_initial[i]);
	printf("\n");
	printf("Key: ");
	for (i = 0; i < nk; i++) printf("%0x ", keyS[i]);
	printf("\n");
	// Now, we start with AES.
	key_expansion(keyS, words, nk);

	add_round_key(text_initial, words, 0);
	printf("\n");
	for(j = 1; j < (nk + 6); j++)
	{
		sub_bytes(text_initial);
		
		initial(text_initial);
		
		shift_rows(text_initial);
		
		mix_columns(text_initial);
		initial(text_initial);
				
		add_round_key(text_initial, words, j);
		
	}
	
	sub_bytes(text_initial);
	
	initial(text_initial);
	
	shift_rows(text_initial);
	initial(text_initial);
	
	printf("Cipher: ");
	
	add_round_key(text_initial, words, nk + 6);
	
	for (i = 0; i < 4; i++) printf("%0x ", text_initial[i]);

	FILE *f = fopen("initial_text_cipher.txt", "w");
	if (f == NULL)
	{
	    printf("Error opening file!\n");
	    exit(1);
	}

	/* print some text */
	for(i = 0; i < 4; i++) fprintf(f, "%0x ", text_initial[i]);
	fclose(f);

	printf("\n");
	printf("\nPress any keyboard key distinct to 'enter' and 'space,'\n");
	printf("and then press enter to finish the program.\n\n");
	scanf("%d", &h);

	return 1;
}
