#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <openssl/sha.h>
#include <openssl/blowfish.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <sys/resource.h> 
#include <sys/time.h>

#ifndef O_NOFOLLOW      //wasn't defined by fcntl.h for some reason
#define O_NOFOLLOW      00400000
#endif
#define ppSize 81
#define blockSize 8 //64 bits
#define buffSize 8192
char buff[buffSize]; //used for general message purposes
struct termios term, baseTerm;
int mode; // 1 for encrypt, 2 for decrypt
void resetCore(struct rlimit *rlp){
	int err;
	err = setrlimit(RLIMIT_CORE, rlp);
	if(err < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		exit(-1);
	}
}
void handleErrors(void)
{
  ERR_print_errors_fp(stdout);
}
void decrypt(unsigned char *hash, char *datafile, char *keyfile){
	int datafd = 0, keyfd = 0;
	EVP_CIPHER_CTX *ctx;
	unsigned char keyOut[16 + blockSize]; //output of decrypted 128 bit key + 64 bits of padding
	unsigned char keyfileContent[16 + blockSize];
	unsigned char *dataContent;
	unsigned char *decryptedData;
	int keylen = 0, fkeylen = 0;
	int i = 0;
	int fileSize = 0;
	int len, f_len;
	unsigned char iv[] = {1,2,3,4,5,6,7,8};

	//open keyfile
	keyfd = open(keyfile, O_RDONLY);
	if(keyfd < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	memset(keyOut, 0, 16);
	memset(keyfileContent, 0, 16);
	i = 0;
	while((read(keyfd, &keyfileContent[i], 1)) != 0){
		i++;
	}
	ctx = EVP_CIPHER_CTX_new();
	if(!EVP_DecryptInit(ctx, EVP_bf_cbc(), hash, iv)){
		printf("error: 1\n");
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	if(!EVP_DecryptUpdate(ctx, keyOut, &keylen, keyfileContent, i)){
		printf("error: 2\n");
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	fkeylen = keylen;
	
	if(!EVP_DecryptFinal(ctx, keyOut + keylen, &keylen)){
		handleErrors();
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	fkeylen = fkeylen + keylen;
	//print out key in hex
	memset(buff, 0, buffSize);
	sprintf(buff, "Key: ");
	write(1, buff, strlen(buff));

	memset(buff, 0, buffSize);
	for(i = 0; i < 16; i++){
		sprintf(&buff[i * 3], " %02x", keyOut[i]);
	}
	sprintf(&buff[48], "\n");
	write(1, buff, strlen(buff));	

	EVP_CIPHER_CTX_free(ctx);

	//decrypt .enc
	//open .enc
	datafd = open(datafile, O_RDONLY);
	if(datafd < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}

	fileSize = lseek(datafd, 0, SEEK_END);
	lseek(datafd, 0, SEEK_SET);

	dataContent = malloc(fileSize + blockSize);
	if(dataContent == NULL){
		ERR_free_strings();
		exit(-1);
	}
	decryptedData = malloc(fileSize + blockSize);
	if(decryptedData == NULL){
		ERR_free_strings();
		exit(-1);
	}
	i = 0;
	while((read(datafd, &dataContent[i], 1)) != 0){
		i++;
	}

	ctx = EVP_CIPHER_CTX_new();
	if(!EVP_DecryptInit(ctx, EVP_bf_cbc(), keyOut, iv)){
		printf("error: 4\n");
		handleErrors();
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	if(!EVP_DecryptUpdate(ctx, decryptedData, &len, dataContent, fileSize)){
		printf("error: 5\n");
		handleErrors();
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	f_len = len;
	if(!EVP_DecryptFinal(ctx, decryptedData + len, &len)){
		printf("error: 6\n");
		handleErrors();
		EVP_CIPHER_CTX_free(ctx);
		ERR_free_strings();
		exit(-1);
	}
	f_len += len;

	EVP_CIPHER_CTX_free(ctx);
	
	memset(buff, 0, buffSize);
	char *tempBuff;
	tempBuff = malloc((fileSize * 3) + 2);
	if(tempBuff == NULL){
		free(dataContent);
		free(decryptedData);
		ERR_free_strings();
		exit(-1);
	}
	
	for(i = 0; i < fileSize; i++){
		sprintf(&tempBuff[i * 3], " %02x", decryptedData[i]);
	}
	sprintf(&tempBuff[fileSize * 3], "\n");
	write(1, tempBuff, strlen(tempBuff));

	memset(tempBuff, 0,  fileSize * 3);
	//print out ascii
	for(i = 0; i < fileSize; i++){
		//check for padding
		if(decryptedData[i] == 4){
			break;
		}
		sprintf(&tempBuff[i], "%c", decryptedData[i]);
	}
	sprintf(&tempBuff[fileSize], "\n");
	write(1, tempBuff, strlen(tempBuff));
	free(tempBuff);

	free(dataContent);
	free(decryptedData);
}
void blowFish(unsigned char* hash, int datafile, int keyfile, char* output){
	int devRand = 0;
	int err = 0, i = 0;
	unsigned char data[16]; //128 bit key
	unsigned char encKey[16 + blockSize];
	unsigned char iv[] = {1,2,3,4,5,6,7,8};
	int fileSize = 0;
	unsigned char *dataContents;
	unsigned char *out;
	int outLen = 0;
	int finalOutLen = 0;
	int enc;
	EVP_CIPHER_CTX *ctx;

	//lock data
	mlock(data, 16);
	//EVP_CIPHER *cipher;
	devRand = open("/dev/urandom", O_RDONLY);
	for(i = 0; i < 16; i++){
		err = read(devRand, &data[i], 1);
		if(err < 0){
			exit(-1);
		}
	}
	memset(buff, 0, buffSize);
	sprintf(buff, "K enc in Hex: ");
	write(1, buff, strlen(buff));

	//print out Kenc in hex
	memset(buff, 0, buffSize);
	for(i = 0; i < 16; i++){
		sprintf(&buff[i * 3], " %02x", data[i]);
	}
	sprintf(&buff[16 * 3], "\n");
	write(1, buff, strlen(buff));

	//load contents of file into program
	fileSize = lseek(datafile, 0, SEEK_END);
	lseek(datafile, 0, SEEK_SET); //reset fd
	dataContents = malloc(fileSize + blockSize);
	mlock(dataContents, fileSize + blockSize);
 	out = malloc(fileSize + blockSize);
 	memset(out, 0, fileSize + blockSize);
	i = 0;
	while(read(datafile, &dataContents[i], 1) != 0){
		i++;
	}

	//encrypt data
	ctx = EVP_CIPHER_CTX_new();
	//cipher = (EVP_CIPHER *)EVP_bf_cbc();
	EVP_EncryptInit(ctx, EVP_bf_cbc(), data, iv);

	if(!EVP_EncryptUpdate(ctx, out, &outLen, dataContents, fileSize)){
		sprintf(buff, "EncryptUpdate Error\n");
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	finalOutLen = outLen;
	if(!EVP_EncryptFinal(ctx, out + outLen, &outLen)){
		sprintf(buff, "EncryptFinal Error\n");
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	finalOutLen = outLen + finalOutLen;


	//create output file
	enc = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0400);
	chmod(output, 0400);
	if(enc < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	//write to output file
	write(enc, out, finalOutLen);

	EVP_CIPHER_CTX_free(ctx);
	free(out);

	finalOutLen = 0;
	//write hash encrypted data to keyfile
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_bf_cbc(), hash, iv);

	if(!EVP_EncryptUpdate(ctx, encKey, &outLen, data, 16)){
		sprintf(buff, "EncryptUpdate Error\n");
		write(1, buff, strlen(buff));
	}
	finalOutLen = outLen;
	if(!EVP_EncryptFinal(ctx, encKey + outLen, &outLen)){
		sprintf(buff, "EncryptFinal Error\n");
		write(1, buff, strlen(buff));
	}
	finalOutLen = finalOutLen + outLen;
	
	EVP_CIPHER_CTX_free(ctx);
	err = write(keyfile, encKey, finalOutLen);
	if(err != finalOutLen){
		printf("Output error\n");
	}
	//data no longer needed
	memset(data, 0, 16);
	munlock(data, 16);
	memset(dataContents, 0, fileSize + 1);
	munlock(dataContents, fileSize + 1);
	free(dataContents);
}

unsigned char* generateKey(char* pp){
	unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*)pp, sizeof(pp), hash);

	return hash;
}
/*Gets a proper user passphrase
@return the inputed passphrase
*/
char* userPrompt(){
		char c = 0;
		int i = 0;
		char *pp1 = malloc(ppSize);
		if(pp1 == NULL){
			return NULL;
		}
		char *pp2 = malloc(ppSize);
		if(pp2 == NULL){
			free(pp1);
			return NULL;
		}
		int err = 0;

		err = mlock(pp1, ppSize);
		if(err < 0){
			free(pp1);
			free(pp2);
			ERR_free_strings();
			return NULL;
		}
		err = mlock(pp2, ppSize);
		if(err < 0){
			free(pp1);
			free(pp2);
			ERR_free_strings();
			return NULL;
		}
		do{
			memset(pp1, 0, ppSize);
			memset(pp2, 0, ppSize);
			sprintf(buff, "Enter a passphrase. It must be at least"
					" 10 characters in length and no longer"
					" than 80 characters.\nPassphrase: ");
			write(1, buff, strlen(buff));

			//get first passphrase
			tcsetattr(0, TCSAFLUSH, &term);
			i = 0;
			//limit max input to 80 characters.
			while(((c = read(0, &pp1[i], 1)) != 0) && pp1[i] != '\n' && i <= 80){
				i++;
			}
			pp1[i] = '\0';

			tcsetattr(0, TCSANOW, &baseTerm);
			sprintf(buff, "Re-enter passphrase:");
			write(1, buff, strlen(buff));

			tcsetattr(0, TCSAFLUSH, &term);
			i = 0;
			//limit max input to 80 characters
			while(((c = read(0, &pp2[i], 1)) != 0) && pp2[i] != '\n' && i < 80){
				i++;
			}
			pp2[i] = '\0';

			tcsetattr(0, TCSANOW, &baseTerm);	
		}while((strncmp(pp1, pp2, ppSize) != 0) || strlen(pp1) < 10);

		free(pp2);
		return pp1;
}
int main(int argc, char **argv){
	int i = 0, err = 0;
	char *pp;
	unsigned char *hash;
	char *outPutFile;
	int datafd, keyfd;
	unsigned char *hashToKey;
	hashToKey = malloc(16);
	ERR_load_crypto_strings();

	//limit core
	rlim_t limit;
	struct rlimit rlp;
	err = getrlimit(RLIMIT_CORE, &rlp);
	if(err < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	limit = rlp.rlim_cur;
	rlp.rlim_cur = 0;
	err = setrlimit(RLIMIT_CORE, &rlp);
	if(err < 0){
		sprintf(buff, "%s\n", strerror(errno));
		write(1, buff, strlen(buff));
		ERR_free_strings();
		exit(-1);
	}
	rlp.rlim_cur = limit; //set rlim to old value to reset when needed

	//check input
	if(argc == 4){
		//handle are 1
		if(strncmp(argv[1], "-e", strlen("-e")) == 0){
			mode = 1;
		}
		else if(strncmp(argv[1], "-d", strlen("-d")) == 0){
			mode = 2;
		}
		else{
			sprintf(buff, "%s not recognized\n", argv[1]);
			write(1, buff, strlen(buff));
			ERR_free_strings();
			exit(0);
		}
		
		//handle arg2
		if(mode == 1){
			outPutFile = malloc(strlen(argv[2]) + 1 + strlen(".enc"));
			sprintf(outPutFile, "%s.enc", argv[2]);

			datafd = open(argv[2], O_RDONLY);
			if(datafd < 0){
				sprintf(buff, "%s\n", strerror(errno));
				write(1, buff, strlen(buff));
				ERR_free_strings();
				exit(-1);
			}

			//handle arg3
			keyfd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0400);
			if(keyfd < 0){
				if(errno == EACCES){
					err = chmod(argv[3], 0600);
					if(err < 0){
						sprintf(buff, "%s\n", strerror(errno));
						write(1, buff, strlen(buff));
						ERR_free_strings();
						exit(-1);
					}
					keyfd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0400);
					if(keyfd < 0){
						sprintf(buff, "%s\n", strerror(errno));
						write(1, buff, strlen(buff));
						ERR_free_strings();
						exit(-1);
					}
				}
				else{
					sprintf(buff, "%s\n", strerror(errno));
					write(1, buff, strlen(buff));
					ERR_free_strings();
					exit(-1);
				}
			}
			chmod(argv[3], 0400);
		}
	}
	else{
		sprintf(buff, "Not enough arguments.\n");
		write(1, buff, strlen(buff));
		exit(0);
	}

	if(isatty(0) == 0){
		//not using a terminal
		exit(-1);
	}
	if(tcgetattr(0, &term) < 0){
		exit(-1);
	}
	baseTerm = term; //duplicate the contents of term

	term.c_lflag &= ~ECHO; //turn off echo
	term.c_lflag |= ECHONL; //echo new line character


	pp = userPrompt();
	//run sha1 over pp to produce Kpass
	hash = generateKey(pp);
	//hash is generated, clear pp, unlock pp, free pp
	memset(pp, 0, ppSize);
	munlock(pp, ppSize);
	free(pp);

	//truncate hash
	for(i = 0; i < SHA_DIGEST_LENGTH - 4; i++){
		hashToKey[i] = hash[i];
	}
	memset(buff, 0, buffSize);
	sprintf(buff, "Kpass Hash: ");
	write(1, buff, strlen(buff));

	memset(buff, 0, buffSize);
	for(i = 0; i < SHA_DIGEST_LENGTH; i++){
		sprintf(&buff[i * 3], " %02x", hash[i]);
	}
	sprintf(&buff[60], "\n");
	write(1, buff, strlen(buff));

	//encrypt mode
	if(mode == 1){
		blowFish(hashToKey, datafd, keyfd, outPutFile);
	}
	//decrypt mode
	else if(mode == 2){
		memset(buff, 0, buffSize);
		sprintf(buff, "Key used to decrypt keyfile: ");
		write(1, buff, strlen(buff));

		memset(buff, 0, buffSize);
		//truncate hash
		for(i = 0; i < SHA_DIGEST_LENGTH - 4; i++){
			sprintf(&buff[i * 3], " %02x", hash[i]);
		}
		sprintf(&buff[(SHA_DIGEST_LENGTH - 4) * 3], "\n");
		write(1, buff, strlen(buff));
		decrypt(hashToKey, argv[2], argv[3]);
	}
	if(mode == 1){
		free(outPutFile);
	}
	resetCore(&rlp);
	munlockall();
	free(hash);
	free(hashToKey);
	ERR_free_strings();
	exit(0);
}