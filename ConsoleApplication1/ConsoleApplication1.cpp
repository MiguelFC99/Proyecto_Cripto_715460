// ConsoleApplication1.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//Miguel Angel Figueroa Castro 715460
//Proyecto criptografia O2021

#include <iostream>
#include <iomanip>
#include <cstring>
#include <fstream>
#include "sodium.h"

//library to signing files

using namespace std;
#define CHUNK_SIZE 4096

static void
crearContra(unsigned char* password) {		//Crear una contraseña cifrada
    unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables: key, nonce, ciphertext, decrypted 
    unsigned char nonce[crypto_secretbox_NONCEBYTES];  
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
    crypto_secretbox_keygen(key);				//con las funciones de libsodium creamos la key y el nonce 
    randombytes_buf(nonce, sizeof nonce);		

    //Declaramos las variables de los archivos que se van a crear
    FILE* fileKey;
    FILE* filePass;
    FILE* fileNonce;

    //Creamos el archivo que guardara la key
    fileKey = fopen("./key", "wb");
    fwrite(key, 1, sizeof(key), fileKey);
    fclose(fileKey);

    //Creamos el archivo que guardara el nonce
    fileNonce = fopen("./nonce", "wb");		
    fwrite(nonce, 1, sizeof(nonce), fileNonce);
    fclose(fileNonce);
   
    //A continuacion solo encriptamos la contraseña dada por el usuario y para esto tambien usamos las variables de nonce y key.
    crypto_secretbox_easy(ciphertext, password, 128, nonce, key);	

    //Guardamos la contraseña encriptada en el archivo, la variable que contiene tal encriptado es ciphertext
    filePass = fopen("./password", "wb");					
    fwrite(ciphertext, 1, sizeof(ciphertext), filePass);
    fclose(filePass);

}


static void decodContra() {				//Decodificar la contraseña cifrada
    unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables: key, nonce, ciphertext, decrypted 
    unsigned char nonce[crypto_secretbox_NONCEBYTES];   
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
    unsigned char decrypted[128];

    FILE* fileKey;
    FILE* filePass;
    FILE* fileNonce;
    //por mayor simplicidad al decodificar, los archivos se guardaran en la carpeta del proyecto y de igual forma de aqui se tomaran osea la ruta raiz
    //abrimos el archivo que tiene la key y la guardamos en su variable correspondiente 
    fileKey = fopen("./key", "rb");		
        fread(key, sizeof(key), 1, fileKey);
        fclose(fileKey);
    //abrimos el archivo que tiene el nonce y la guardamos en su variable correspondiente 
    fileNonce = fopen("./nonce", "rb");	
    fread(nonce, sizeof(nonce), 1, fileNonce);
    fclose(fileNonce);
    //abrimos el archivo que tiene la contraseña y guardamos su contenido en la variable 
    filePass = fopen("./password", "rb");	
    fread(ciphertext, sizeof(ciphertext), 1, filePass);
    fclose(filePass);
     
    //Con la funcion de libsodium enviamos la contraseña extraida del archivo para decifrarse y si la funcion no devuelve un 0 es que hubo un error 
    string res = crypto_secretbox_open_easy(decrypted, ciphertext, crypto_secretbox_MACBYTES + 128, nonce, key) != 0 ? "error" 
        : "La informacion con el archivo es correcta se ha descifrado la password ";
    //Aqui solo mostramos la contraseña 
    printf(" %s %s \n\n",res.c_str(),decrypted);
}

static int
encryptArchivo(const char* target_file, const char* source_file,		//Encriptamos un archivo elegido por el ususario 
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{	//Definimos variables 
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    //Definimos las variables de los archivos donde vamos a leer y a escribir
    FILE* fileOrig;
    FILE* fileEncrypt;
    
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;
    //instanciamos archivo original y creamos el archivo donde se guardara encriptado
    fileEncrypt = fopen(source_file, "rb");
    fileOrig = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fileOrig);
    do {		//Encriptacion del archivo
                //Mientras no sea el final del archivo
        rlen = fread(buf_in, 1, sizeof buf_in, fileEncrypt);
        eof = feof(fileEncrypt);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fileOrig);
    } while (!eof);	
    //cerramos los archivos usados.
    fclose(fileOrig);
    fclose(fileEncrypt);
    return 0;
}

static int
decryptArchivo(const char* target_file, const char* source_file,		//Desencriptado de archivo
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{//definimos variables
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fileDec, * fileEncr;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;
    //abrimos el archivo encriptado y creamos el archivo desencriptado
    fileEncr = fopen(source_file, "rb");
    fileDec = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fileEncr);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {//desencriptamos el archivo
        rlen = fread(buf_in, 1, sizeof buf_in, fileEncr);
        eof = feof(fileEncr);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t)out_len, fileDec);
    } while (!eof); //terminamos llegando al final del archivo

    ret = 0;
ret:
    //cerramos el archivo
    fclose(fileDec);
    fclose(fileEncr);
    return ret;
}

static void signString(unsigned char* str) {	//Realizamos la firma
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    //firma de llaves publicas y privadas
    crypto_sign_keypair(pk, sk);


    FILE* filepk; 
    FILE* filesk; 
    FILE* fileS1;
    FILE* fileLen;

    //guardamos public key en un archivo pk
    filepk = fopen("./pk", "wb");
    fwrite(pk, 1, sizeof(pk), filepk);
    fclose(filepk);
    //guardamos private key en un archivo sk
    filesk = fopen("./sk", "wb");
    fwrite(sk, 1, sizeof(sk), filesk);
    fclose(filesk);

    unsigned char signed_message[crypto_sign_BYTES + 128];
    unsigned long long signed_message_len;

    //tomamos el mensaje y lo guardamos en una variale firmada, junto con su longitud
    crypto_sign(signed_message, &signed_message_len, str, 128, sk);


    //guardamos el mensaje firmado en un archivo signedmessage
    fileS1 = fopen("./Firma", "wb");
    fwrite(signed_message, 1, sizeof(signed_message), fileS1);
    fclose(fileS1);
    //guardamos la longitud del mensaje firmado en un archivo signlen
    fileLen = fopen("./FirmaLen", "wb");
    fwrite(&signed_message_len, 1, sizeof(signed_message_len), fileLen);
    fclose(fileLen);
}


static void verifyString() {		//tomamos el mensaje firmado y verificamos que no haya sido forjado
    //definimos variable
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char signed_message[crypto_sign_BYTES + 128];
    unsigned long long signed_message_len;

    //abrimos archivos y guardamos su contenido en variables
    FILE* filepk;
    FILE* filesk;
    FILE* fileS1;
    FILE* fileLen;

    filepk = fopen("./pk", "rb");
    fread(pk, sizeof(pk), 1, filepk);
    fclose(filepk);

    filesk = fopen("./sk", "rb");
    fread(sk, sizeof(sk), 1, filesk);
    fclose(filesk);

    fileS1 = fopen("./Firma", "rb");
    fread(signed_message, sizeof(signed_message), 1, fileS1);
    fclose(fileS1);

    fileLen = fopen("./FirmaLen", "rb");
    fread(&signed_message_len, sizeof(long long), 1, fileLen);
    fclose(fileLen);

    //definimos variables donde guardaremos el mensaje sin firmar y su longitud
    unsigned char mf[128];
    unsigned long long mlen;

    //verificamos la veracidad del mensaje Si es correcta entonces mandamos un print de correcto, sino simplemente 
    string res = crypto_sign_open(mf, &mlen, signed_message, signed_message_len, pk) != 0 ? "error" : "Firma Correcta";
    cout << res;
}

int main(int argc, char* argv[])
{   
    unsigned char password[128];
    unsigned char firma[128];
    int choice;
    do
    {
        cout << "\nMenu\n";
        cout << "1. Generacion y Recuperacion de claves hacia o desde 1 archivo\n";
        cout << "2. Cifrado de Archivos\n";
        cout << "3. Descifrado de Archivos\n";
        cout << "4. Firma de Archivos\n";
        cout << "5. Verificación de Firma de Archivos\n";
        cout << "6. Salir\n";
        cout << "--------------------------------------------\n";
        cout << "\nElige 1, 2, 3, 4, 5 o 6: ";
        cin >> choice;
        switch (choice)
        {
        case 1:
            //pedimos al usuario ingresar su contraseña a encriptar
            cout << "\n Opcion 1: Generacion y Recuperacion de claves\n";
            printf("Ingresa una password...\n");
            cin >> password;
            //la encriptamos
            crearContra(password);
            //la decodificamos para mostrar que fue correcto
            decodContra();
            break;
        case 2:
            //pedimos al usuario una direccion de su archivo a encriptar
            cout << "\nOpcion 2: Cifrado de Archivos\n ";
            char file[128];
            printf("Ingresa el directorio del archivo a encriptar...\n");
            cin >> file;
            //generamos una llave
            unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
            crypto_secretstream_xchacha20poly1305_keygen(key);
            //encriptamos el archivo
            if (encryptArchivo("./archivoCifrado", file, key) != 0) {
                return 1;
            }
            cout << "\nSe ha encriptado el archivo correctamente\n ";
            break;
        case 3:
            cout << "\nOpcion 3: Descifrado de Archivos\n ";
            
            if (decryptArchivo("./archivoDescifrado", "./archivoCifrado", key) != 0) {
                return 1;
            }
            cout << "\nSe ha decifrado tu archivo puedes verlo en la carpeta del proyecto -- archivoDescifrado\n ";
            break;
        case 4:
            cout << "\nOpcion 4: Firma de Archivos\n";
            //Realizamos la firma
            printf("Escriba en mensaje a firmar\n");
            cin >> firma;
            
            signString(firma);
            
            
            break;
        case 5:
            cout << "\nOpcion 5: Verificacion de firma de Archivos\n";
            //verificamos la firma
            verifyString();
            break;
        default:
            cout << "\nElemento invalido, por favor seleccione una opcion valida.\n";
            break;
        }
    } while (choice != 6);
    return 0;
}       
