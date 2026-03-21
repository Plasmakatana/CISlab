#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
char* chars="abcdefghijklmnopqrstuvwxyz";
char* uchars="ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void caesar(char input[256],int key){
  for(int i=0;i<256;i++){
    char c=input[i];
    if(c==' '){input[i]='%';}
    else if(isupper(input[i])){
      int ci=c-'A';
      input[i]=uchars[(ci+key)%26];
    }
    else{
      int ci=c-'a';
      input[i]=chars[(ci+key)%26];
    }
  }
}
void caesarDecrypt(char input[256],int key){
  for(int i=0;i<256;i++){
    char c=input[i];
    if(c=='%'){input[i]=' ';}
    else if(isupper(input[i])){
      int ci=c-'A';
      if(ci-key<0){ci+=26;}
      input[i]=uchars[(ci-key)%26];
    }
    else{
      int ci=c-'a';
      if(ci-key<0){ci+=26;}
      input[i]=chars[(ci-key)%26];
    }
  }
}

void removeNewline(char *s){
    int len=strlen(s);
    while(len>0 && s[len-1]=='\n'){
      s[len-1]='\0';
    }
}
int *makeKeyOrder(char *key,int klen){
    int *order = malloc(klen * sizeof(int));
    int used[20] = {0};

    for(int i=0;i<klen;i++){
        int minIndex=-1;
        for(int j=0;j<klen;j++){
            if(!used[j] && (minIndex==-1 || key[j]<key[minIndex])){
                minIndex=j;
            }
        }
        order[minIndex]=i;
        used[minIndex]=1;
    }
    return order;
}
void colTransEncrypt(char input[256], char *key, char output[256]){
    int len=strlen(input);
    int klen=strlen(key);

    int rows = (len + klen - 1) / klen;
    char mat[rows][klen];
    memset(mat,'_',sizeof(mat));

    int idx=0;
    for(int r=0;r<rows;r++){
        for(int c=0;c<klen;c++){
            if(idx<len){
                mat[r][c]=input[idx++];
            }
        }
    }

    int *order = makeKeyOrder(key,klen);
    idx=0;
    for(int k=0;k<klen;k++){
        for(int c=0;c<klen;c++){
            if(order[c]==k){
                for(int r=0;r<rows;r++){
                    output[idx++]=mat[r][c];
                }
            }
        }
    }
    output[idx]='\0';
    free(order);
}

void colTransDecrypt(char input[256], char *key, char output[256]){
    int len=strlen(input);
    int klen=strlen(key);
    int rows = (len + klen -1)/klen;

    char mat[rows][klen];
    memset(mat,'_',sizeof(mat));

    int *order=makeKeyOrder(key,klen);

    int idx=0;
    for(int k=0;k<klen;k++){
        for(int c=0;c<klen;c++){
            if(order[c]==k){
                for(int r=0;r<rows;r++){
                    mat[r][c]=input[idx++];
                }
            }
        }
    }

    idx=0;
    for(int r=0;r<rows;r++){
        for(int c=0;c<klen;c++){
            if(mat[r][c]!='_'){
                output[idx++]=mat[r][c];
            }
        }
    }
    output[idx]='\0';
    free(order);
}

int main(){
  char p[256], key[20];
  char cipher[256], dec[256];
  int k;
  printf("Enter plaintext:");
  fgets(p,sizeof(p),stdin);
  printf("\nEnter key:");
  scanf("%d",&k);
  getchar();
  caesar(p,k);
  printf("\n---Caesar Cipher---");
  printf("\nEncrypted: %s\n",p);
  caesarDecrypt(p,k);
  printf("\nDecrypted: %s\n",p);
  printf("\n---Column Transpose Encryption---");
  removeNewline(p);
  printf("\nEnter numeric key (like 3142):");
  fgets(key, sizeof(key), stdin);
  removeNewline(key);
  colTransEncrypt(p, key, cipher);
  printf("\nEncrypted string:%s",cipher);
  colTransDecrypt(cipher, key, dec);
  printf("\nDecrypted string:%s",dec);
  return 0;
}


