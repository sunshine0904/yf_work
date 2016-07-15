//gcc -g hmac_sha1_demo2.c -o hmac_sha1_demo2 -lcrypto --std=c99

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

//variable about hmac_sha
unsigned char key[16] = {0x0};
unsigned char key_len = 16;
unsigned char data[16] = {0x0};
unsigned char data_len = 16;
//unsigned char out[16] = {0x0};
//unsigned char out_len = 16;

unsigned char ip1[4] = {0xc0,0xa8,0x1,0x1};
unsigned char ip2[4] = {0xc0,0xa8,0x1,0x2};
unsigned char ip3[4] = {0xc0,0xa8,0x1,0x3};
unsigned char ip4[4] = {0xc0,0xa8,0x1,0x4};
unsigned char ip5[4] = {0xc0,0xa8,0x1,0x5};



int main() {

	    // The secret key for hashing
    //const char key[] = "012345678";

    // The data that we're going to hash
    //char data[] = "hello world";

	    //initital out
		//memset(out,0,16);
		
		//initital key
		memset(key,0,16);
		memcpy(key,ip1,4);
	
		//initital data
		memset(data,0,16);
		memcpy(data,ip2,4);
		memcpy(data+4,ip3,4);
		memcpy(data+8,ip4,4);
		memcpy(data+12,ip5,4);


		
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.
    unsigned char* result;
    unsigned int len = 20;

    result = (unsigned char*)malloc(sizeof(char) * len);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);


	printf("encry_data:");
	
	for(int j = 0;j<16;j++)
		{
			printf("%02x ",data[j]);
		}
		printf("\n");



    printf("HMAC digest: ");

    for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)result[i]);

    printf("\n");

    free(result);

    return 0;
}