//
//  Li-cryptogator.c
//
//  Created by Yunze Li on 2/1/16.
//  Copyright © 2016 Yunze Li. All rights reserved.
//

#include <stdio.h>
#include <gpg-error.h>
#include <gcrypt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>

#define GCRYPT_NO_DEPRECATED

int aes(char *plaintext, size_t size, int alg, const char *name){
	//initializing the library, use a security memory
	//check the version
	if(!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)){
		//initializing the library, use a security memory00000
		    //check the version
		    if(!gcry_check_version(GCRYPT_VERSION)){
		        fputs("libgcrypt version mismatch\n", stderr);
		        exit(2);
		    }
		    //allocate the 16k secure memory pool
		    gcry_control(GCRYCTL_INIT_SECMEM, 1024*1024, 0);
		    //now resume the warning function
		    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
		    //the initialization is complete
		    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
		    //check if it's already initialized successfully
		    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
		    {
		      fputs ("libgcrypt has not been initialized\n", stderr);
		      abort ();
		    }
	}
    //finish initialize, start to crypto
	size_t txtLenght = size;
	char *out = malloc(size);

	//use two hanlders to do the AES128 CTR mode
	//this method is not explicited in the library document
	//I worked for the whole week to figure out what happened in here
	//I don't know why the auther did't mention that
	//but it really a hard time and I hate this library
	gcry_cipher_hd_t handler1;
	gcry_cipher_hd_t hangler2;

	//declare key length
	int algo = gcry_cipher_map_name(name);
	size_t ctrLen = gcry_cipher_get_algo_blklen(alg);
	size_t keyLen = gcry_cipher_get_algo_keylen(alg);

	//allocate the key pointer
	char *key = malloc(keyLen);
	char *counter = malloc(ctrLen);

	//use two handlers to do the same
	gcry_cipher_open(&handler1, algo, GCRY_CIPHER_MODE_CTR, 0);
	gcry_cipher_open(&hangler2, algo, GCRY_CIPHER_MODE_CTR, 0);

	gcry_cipher_setkey(handler1, key, keyLen);
	gcry_cipher_setkey(hangler2, key, keyLen);

	gcry_cipher_setctr(handler1, counter, ctrLen);
	gcry_cipher_setctr(hangler2, counter, ctrLen);


	//printf("Original File: \nText:");
	//printf("%sASC ii: ", plaintext);
	//int i=0;
	//for(i=0; i < txtLenght; i++){
		//printf("%02x", (unsigned char) plaintext[i]);
	//}

    //start to encrypt
	gcry_cipher_encrypt(handler1, out, txtLenght, plaintext, txtLenght);

	//print out crypotoText
	//printf("\n");
	//printf(name);
	//printf(" CTR Mode: CrypotoText = ");
	//for(i = 0; i < txtLenght; i++){
	   // printf("%02x", (unsigned char) out[i]);
	//}

	//start to decrypt
	gcry_cipher_decrypt(hangler2, out, txtLenght, NULL, 0);

	//printf("\n\nAfter Decrypt:\nASC ii: ");
	//for(i = 0; i < txtLenght; i++){
		//printf("%02x", (unsigned char) out[i]);
	//}
	//printf("\nText: %s", out);
	//printf("\n\n");

	//close the two handlers
	gcry_cipher_close(handler1);
	gcry_cipher_close(hangler2);

	//free the space
	free(out);
	free(key);
	free(counter);
	return 0;
}


gcry_sexp_t sexp_new(const char *str) {
	gcry_error_t error;

	gcry_sexp_t sexp;
	size_t len = strlen(str);
	if ((error = gcry_sexp_new(&sexp, str, len, 1))) {
		printf("Error in sexp_new(%s): %s\nSource: %s\n", str, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	return sexp;
}

char* sexp_string(gcry_sexp_t sexp) {
	size_t buf_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	char *buffer = (char*)gcry_malloc(buf_len);
	if (buffer == NULL) {
		printf("gcry_malloc(%ld) returned NULL in sexp_string()!\n", buf_len);
		exit(1);
	}
	if (0 == gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buffer, buf_len)) {
		printf("gcry_sexp_sprint() lies!\n");
		exit(1);
	}
	return buffer;

	// This should be freed with gcry_free(buffer);
}

void generate_key(char **public_key, char **private_key, const char* name) {
	gcry_error_t error;

	// Generate a reduced strength (to save time) RSA key
	gcry_sexp_t params = sexp_new(name);
	gcry_sexp_t r_key;
	if ((error = gcry_pk_genkey(&r_key, params))) {
		printf("Error in gcry_pk_genkey(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t public_sexp  = gcry_sexp_nth(r_key, 1);
	gcry_sexp_t private_sexp = gcry_sexp_nth(r_key, 2);

	*public_key = sexp_string(public_sexp);
	*private_key = sexp_string(private_sexp);
}

char* encrypt(char *public_key, char *plaintext){
	gcry_error_t error;

	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, plaintext, 0, NULL))) {
		printf("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("Error in gcry_sexp_build() in encrypt() at %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t public_sexp = sexp_new(public_key);
	gcry_sexp_t r_ciph;
	if ((error = gcry_pk_encrypt(&r_ciph, data, public_sexp))) {
		printf("Error in gcry_pk_encrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	return sexp_string(r_ciph);
}

char* decrypt(char *private_key, char *ciphertext){
	gcry_error_t error;
	gcry_sexp_t data = sexp_new(ciphertext);

	gcry_sexp_t private_sexp = sexp_new(private_key);
	gcry_sexp_t r_plain;
	if ((error = gcry_pk_decrypt(&r_plain, data, private_sexp))) {
		printf("Error in gcry_pk_decrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_mpi_t r_mpi = gcry_sexp_nth_mpi(r_plain, 0, GCRYMPI_FMT_USG);

	unsigned char *plaintext;
	size_t plaintext_size;
	if ((error = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &plaintext, &plaintext_size, r_mpi))) {
		printf("Error in gcry_mpi_aprint(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	return plaintext;
}

char* sign(char *private_key, char *document){
	gcry_error_t error;

	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, document, 0, NULL))) {
		printf("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("Error in gcry_sexp_build() in sign() at %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t private_sexp = sexp_new(private_key);
	gcry_sexp_t r_sig;
	if ((error = gcry_pk_sign(&r_sig, data, private_sexp))) {
		printf("Error in gcry_pk_sign(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	return sexp_string(r_sig);
}

short verify(char *public_key, char *document, char *signature){
	gcry_error_t error;

	gcry_mpi_t r_mpi;
	if ((error = gcry_mpi_scan(&r_mpi, GCRYMPI_FMT_HEX, document, 0, NULL))) {
		printf("Error in gcry_mpi_scan() in encrypt(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", r_mpi))) {
		printf("Error in gcry_sexp_build() in sign() at %ld: %s\nSource: %s\n", erroff, gcry_strerror(error), gcry_strsource(error));
		exit(1);
	}

	gcry_sexp_t sig = sexp_new(signature);

	gcry_sexp_t public_sexp = sexp_new(public_key);
	short good_sig = 1;
	if ((error = gcry_pk_verify(sig, data, public_sexp))) {
		if (gcry_err_code(error) != GPG_ERR_BAD_SIGNATURE) {
			printf("Error in gcry_pk_verify(): %s\nSource: %s\n", gcry_strerror(error), gcry_strsource(error));
			exit(1);
		}
		good_sig = 0;
	}
	return good_sig;
}

int comp (const void * elem1, const void * elem2)
{
    double f = *((double*)elem1);
    double s = *((double*)elem2);
    if (f > s) return  1;
    if (f < s) return -1;
    return 0;
}

void rsa(const char *name, char *plaintext, double *result, char *description){
	//initialize
	char *public_key, *private_key;
	struct timespec start, end;

	generate_key(&public_key, &private_key, name);
	int i=0;
	int temp=0;

	for(i=0; i<100; i++){
	    clock_gettime(0x01, &start);
	    //rsa(name, plaintext);
	    //printf("\nFor %s:\n", description);
	    //printf("%s\n", public_key);
	    //printf("%s\n", private_key);

	    //printf("Plaintext:\n%s\n\n", plaintext);

	    char *ciphertext;
	    ciphertext = encrypt(public_key, plaintext);
	    //printf("Ciphertext:\n%s\n", ciphertext);

	    char *decrypted;
	    //decrypted = decrypt(private_key, ciphertext);
	    //printf("Decrypted Plaintext:\n%s\n\n", decrypted);

	    char *signature;
	    signature = sign(private_key, plaintext);
	    //printf("Digital Signature:\n%s\n", signature);

	    //if (verify(public_key, plaintext, signature)) {
	    	//printf("Congratulation! The Digital Signature is VERIFIED!\n\n");
	    //}
	    //else {
	        //printf("Sorry, the Digital Signature is NOT CORRECT!\n\n");
	    //}

	    clock_gettime(0x01, &end);
	    result[i]=end.tv_sec*1000000000.0+end.tv_nsec;
	    result[i]=result[i]-start.tv_sec*1000000000.0-start.tv_nsec;
	    printf("%s: running time: %.3lf us\n",description, result[i]/1000.0 );
	}

	 //sort the result
	 qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

	 //calculate the median
	 printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

	 //calculate the mean
	 for(i=0; i<100; i++){
	     temp += result[i]/1000.0;
	 }
	 printf("  the mean is: %.3lf\n\n", temp/100.0);



}

void hmac(char *plaintext, int algo, char *description){
	/* Test for arg string */

	    // Length of message to encrypt
	    int msg_len = strlen(plaintext );

	    /* get the length that is enough for algorithm MD5
	     * by gcry_md_get_algo_dlen function */
	    int hash_len = gcry_md_get_algo_dlen( algo );

	    /* output sha1 hash - this will be binary data */
	    //allocate a char[], prepare for hash
	    unsigned char hash[ hash_len ];

	    //convert each char(8 bit) into 2 hex digit(4 bit), so we need twice length plus 1(for "\0")
	    //allocate enough memory for output and pointer "out" points to this buffer
	    char *out = (char *) malloc( sizeof(char) * ((hash_len*2)+1) );

	    //hash the message into the char[] hash
	    gcry_md_hash_buffer( algo, hash, plaintext, msg_len );

	    //printf the result
	    //printf("%s hash code is:", description);

	    /* output each char in hash, use hex representation, each char
	     * need to be 2 digits, compensate 0 if only one digit */
	    //int i;
	    //for ( i = 0; i < hash_len; i++ ) {
	        //printf ( "%02x", hash[i] );
	    //}

	    //printf("\n\n");
	    free( out );

}

void hmacds(char *plaintext, int algo, char *description, const char *name){
	/* Test for arg string */

	    // Length of message to encrypt
	    int msg_len = strlen(plaintext );

	    /* get the length that is enough for algorithm MD5
	     * by gcry_md_get_algo_dlen function */
	    int hash_len = gcry_md_get_algo_dlen( algo );

	    /* output sha1 hash - this will be binary data */
	    //allocate a char[], prepare for hash
	    unsigned char hash[ hash_len ];

	    //convert each char(8 bit) into 2 hex digit(4 bit), so we need twice length plus 1(for "\0")
	    //allocate enough memory for output and pointer "out" points to this buffer
	    char *output= (char *) malloc((hash_len*2) + 1);

	    //hash the message into the char[] hash
	    gcry_md_hash_buffer( algo, hash, plaintext, msg_len );

	    printf("For Digital Signature:\n");

	    //printf the result
	    //printf("%s hash code is:", description);

	    /* output each char in hash, use hex representation, each char
	     * need to be 2 digits, compensate 0 if only one digit */
	    int i;
	    for ( i = 0; i < hash_len; i++ ) {
	        //printf ( "%02x", hash[i] );
	        sprintf(output +i*2, "%02x", hash[i]);
	    }

	    printf( "\n");


	    //initialize
	    char *public_key, *private_key;
	    generate_key(&public_key, &private_key, name);

	    char *ciphertext;
	    ciphertext = encrypt(public_key, output);

	    char *decrypted;
	    decrypted = decrypt(private_key, ciphertext);

	    char *signature;
	    signature = sign(private_key, output);
	    printf("Signature:\n%s\n", signature);

	    if (verify(public_key, output, signature)) {
	    	printf("This Digital Signature is VERIFIED!\n\n");
	    } else {
	    	printf("Sorry, this Digital Signature is NOT CORRECT!\n\n");
	    }

	    free( output );
}


long GetFileSize(const int filedf){
    struct stat statbuf;
    if(fstat(filedf, &statbuf)==-1)
    {
        printf("file error!\r\n");
        return -1;
    }
    return statbuf.st_size;
}

char *readFile(char *fileName, int *fileId,int* length)
{

    *fileId= open(fileName, O_RDWR);
    if(fileId==-1)
    {
        printf("read file fail!\r\n");
        exit(-1);
    }
    long size=GetFileSize(*fileId);
    char* data=(char*)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, *fileId, 0);
    *length=size;
    return data;
}
void CloseFile(char* addr,int fileId,int length)
{
	munmap(addr,length);
	close(fileId);
}



int main(int argc, char **argv) {


	/**************************************************************
	*Initialize variables
	**************************************************************/
	int algo;
	char *name;
        char *filename = argv[1];
	struct timespec start, end;
	double result[100] = {0};
	double temp=0;

	/**************************************************************
    * Pre-processing the input file
    **************************************************************/
	int FileId;
	int length;
	//read the file
	char *rawText= readFile(filename, &FileId,&length);
	char *plaintext=(char*)malloc(2*length+1);
	//now start to pre-process
	int i=0;
    for(i=0;i<length;i++)
	{
		char char1=rawText[i]/16;
		char char2=rawText[i]%16;

		if(char1<10)
			char1+='0';
		else
			char1 += 'A'-10;
		if(char2<10)
			char2+='0';
		else
			char2 += 'A'-10;

		plaintext[2*i]=char1;
		plaintext[2*i+1]=char2;
	}
    //add the 0 to the end
	plaintext[2*length]=0;

	/**************************************************************
	 * For AES Mode
	 **************************************************************/
	//AES128 CTR Mode
	//set variable value
	algo = GCRY_CIPHER_AES;
	name = "aes128";

	//do it 100 times
	for(i=0; i<101; i++){
		clock_gettime(0x01, &start);
		aes(rawText, length, algo, name);
		clock_gettime(0x01, &end);
		if(i==0) continue;
		result[i-1]=end.tv_sec*1000000000.0+end.tv_nsec;
		result[i-1]=result[i-1]-start.tv_sec*1000000000.0-start.tv_nsec;
		printf("AES128 CTR Mode: running time: %.3lf us\n", result[i-1]/1000.0 );
	}

    //sort the result
	qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

	//calculate the median
	printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

	//calculate the mean
    for(i=0; i<100; i++){
    	temp += result[i]/1000.0;
    }
    printf("  the mean is: %.3lf\n\n\n", temp/100.0);




    //AES256 CTR Mode
    //set variable value
    algo = GCRY_CIPHER_AES;
    name = "aes256";

    //do it 100 times
    for(i=0; i<101; i++){
    	clock_gettime(0x01, &start);
    	aes(rawText, length, algo, name);
    	clock_gettime(0x01, &end);
    	if(i==0) continue;
    	result[i-1]=end.tv_sec*1000000000.0+end.tv_nsec;
    	result[i-1]=result[i-1]-start.tv_sec*1000000000.0-start.tv_nsec;
    	printf("AES256 CTR Mode: running time: %.3lf us\n", result[i-1]/1000.0 );
    }

    //sort the result
    qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

    //calculate the median
    printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

    //calculate the mean
    temp=0;
    for(i=0; i<100; i++){
        temp += result[i]/1000.0;
    }
    printf("  the mean is: %.3lf\n\n", temp/100.0);


	/**************************************************************
	 * For RSA
	 **************************************************************/

    //RSA1024
    name = "(genkey (rsa (transient-key) (nbits 4:1024)))";
    char *description = "RSA1024";
    rsa(name, plaintext, result, description);


    //RSA4096
    name = "(genkey (rsa (transient-key) (nbits 4:4096)))";
    description = "RSA4096";
    rsa(name, plaintext, result, description);



    /*****************************************************************
     *For HMAC
     ****************************************************************/

    //HMAC MD5
    algo = GCRY_MD_MD5;
    description = "MD5";
    for(i=0; i<100; i++){
        clock_gettime(0x01, &start);
        //printf("plaintext is %s\n", plaintext);
        hmac(plaintext, algo, description);
        clock_gettime(0x01, &end);
        result[i]=end.tv_sec*1000000000.0+end.tv_nsec;
        result[i]=result[i]-start.tv_sec*1000000000.0-start.tv_nsec;
        printf("HMAC MD5 running time: %.3lf us\n", result[i]/1000.0 );
    }
    //sort the result
    qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

    //calculate the median
    printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

    //calculate the mean
    temp=0;
    for(i=0; i<100; i++){
        temp += result[i]/1000.0;
    }
    printf("  the mean is: %.3lf\n\n", temp/100.0);


    //HMAC SHA1
    algo = GCRY_MD_SHA1;
    description = "SHA1";
    for(i=0; i<100; i++){
        clock_gettime(0x01, &start);
        //printf("plaintext is %s\n", plaintext);
        hmac(plaintext, algo, description);
        clock_gettime(0x01, &end);
        result[i]=end.tv_sec*1000000000.0+end.tv_nsec;
        result[i]=result[i]-start.tv_sec*1000000000.0-start.tv_nsec;
        printf("HMAC SHA1 running time: %.3lf us\n", result[i]/1000.0 );
    }
    //sort the result
    qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

    //calculate the median
    printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

    //calculate the mean
    temp=0;
    for(i=0; i<100; i++){
        temp += result[i]/1000.0;
    }
    printf("  the mean is: %.3lf\n\n", temp/100.0);


    //HMAC SHA256
    algo = GCRY_MD_SHA256;
    description = "SHA256";
    for(i=0; i<100; i++){
        clock_gettime(0x01, &start);
        //printf("plaintext is %s\n", plaintext);
        hmac(plaintext, algo, description);
        clock_gettime(0x01, &end);
        result[i]=end.tv_sec*1000000000.0+end.tv_nsec;
        result[i]=result[i]-start.tv_sec*1000000000.0-start.tv_nsec;
        printf("HMAC SHA256 running time: %.3lf us\n", result[i]/1000.0 );
    }
    //sort the result
    qsort (result, sizeof(result)/sizeof(*result), sizeof(*result), comp);

    //calculate the median
    printf("\nthe median is: %.3lf", (result[48]+result[49])/2000.0);

    //calculate the mean
    temp=0;
    for(i=0; i<100; i++){
        temp += result[i]/1000.0;
    }
    printf("  the mean is: %.3lf\n\n", temp/100.0);


    /*****************************************************************
    *For Digital Signature
    ****************************************************************/


    //HMAC SHA256, print out digital signature
    algo = GCRY_MD_SHA256;
    description = "SHA256";;
    name = "(genkey (rsa (transient-key) (nbits 4:4096)))";
    hmacds(plaintext, algo, description, name);

    CloseFile(plaintext,FileId,length);
	return 0;
}
