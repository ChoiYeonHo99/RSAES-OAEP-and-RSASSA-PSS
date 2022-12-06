# RSAES-OAEP-and-RSASSA-PSS
## 문제
표준문서 IETF RFC 8017에 명시된 RSA 공개키 암호체계 PKCS #1 버전 2.2를 구현한다. PKCS #1에는  
RSAES-OAEP (Encryption/decryption Scheme based on the Optimal Asymmetric Encryption Padding)와  
RSASSA-PSS (Signature Scheme with Appendix based on the Probabilistic Signature Scheme)가 들어있  
다. RSAES-OAEP는암복호알고리즘이고, RSASSA-PSS는확률적전자서명알고리즘이다. RSA의키의  
길이는 2048비트로 한다.
## RSAES-OAEP
RSAES-OAEP 기법은 암호화할 메시지 M (Message)을 아래 그림과 같은 과정을 거쳐 EM (Encoded
Message)으로 변환한 후, 공개키 (𝑒, 𝑛)을 사용하여 EM^𝑒 mod 𝑛을 계산한다.

![image](https://user-images.githubusercontent.com/70682926/205847708-f1acfad8-ff25-4a24-85e8-e78cf6d08788.png)

• 암호화할 메시지에 라벨을 붙일 수 있는데, Hash(L)은 그 라벨을 해시한 값이다.  
• Padding String은 값이 0x00인 바이트열이다.  
• ‘01’과 ‘00’은 값이 각각 0x01과 0x00인 단일 바이트이다.  
• 해시함수는 길이가 최소 224 비트인 SHA-2 계열의 함수를 사용한다.  
• 난수 Seed의 길이는 해시함수의 길이와 같이 한다.  
• Encoded Message의 길이는 RSA 키의 길이인 RSAKEYSIZE (2048 비트)와 일치해야 한다.
## RSASSA-PSS
RSASSA-PSS 기법은 서명할 메시지 M을 아래 그림과 같은 과정을 거쳐 EM으로 변환한 후, 개인키  
(𝑑, 𝑛)을 사용하여 EM𝑑 mod 𝑛을 계산한다.  

![image](https://user-images.githubusercontent.com/70682926/205847901-450ece1f-04da-41a4-9041-3aab9246d3ff.png)

• 해시함수는 길이가 최소 224 비트인 SHA-2 계열의 함수를 사용한다.  
• 난수 salt의 길이는 해시함수의 길이와 같이 한다.  
• M’의 처음 8 바이트는 0x00으로 채운다.  
• PS는 길이에 맞춰 0x00으로 채운다.  
• TF는 1 바이트이며 0xBC로 채운다.  
• mHash = Hash(M), H = Hash(M’)이다.  
• EM의 길이는 RSA 키의 길이인 RSAKEYSIZE (2048 비트)와 일치해야 한다.  
• EM의 가장 왼쪽 비트 (MSB)가 1이면 강제로 0으로 바꾼다.
## GMP 라이브러리 설치
GNU GMP 라이브러리는 정수의 크기가 2^64보다 큰 수를 계산하기 위해 개발된 패키지이다. 이번 과제에  
서 기본적으로 제공하는 rsa_generate_key()와 rsa_cipher() 함수는 GMP 라이브러리를 사용하고  
있다. 이들 함수를 활용하려면 각자 환경에 맞는 GMP 라이브러리를 설치해야 한다. GMP는 Linux,  
macOS, Windows 등 대부분의 환경을 지원한다. GMP를 먼저 설치하고 과제를 진행한다.  

• Linux 환경에서는 터미널을 열고 다음 두 명령어를 실행한다.  
% sudo apt update  
% sudo apt install libgmp-dev  

• macOS 환경에서는 먼저 Homebrew가 설치되어 있어야 한다 (프로젝트 #3 참조). 터미널을 열고  
다음 명령어를 실행한다.  
% brew install gmp  

이번 과제에서는 GMP 라이브러리 설치가 필요하지만 당장 이를 이용해서 코딩할 부분은 없다. 그러  
나 다음 과제에서는 필요하다. GMP 함수를 사용하려면 #include <gmp.h>를 하고, gcc 링크시 -lgmp  
옵션을 사용해야 한다. 예를 들어 % gcc -o sample sample.c -lgmp가 그 활용이다.
## 함수 구현
PKCS #1 버전 2.2에 필요한 함수를 아래 열거한 프로토타입을 사용하여 구현한다. 각 함수에 대한  
요구사항은 다음과 같다.  

• void rsa_generate_key(void *e, void *d, void *n, int mode) – 길이가 RSAKEYSIZE  
인 e, d, n을 생성한다. mode가 0이면 표준 모드로 e = 65537을 선택하고, 0이 아니면 무작위로  
선택한다. 이 함수는 기본으로 제공한다.  

• static int rsa_cipher(void *m, const void *k, const void *n) – 𝑚 ← 𝑚^𝑘 mod 𝑛을  
계산한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다. 내부에서만 사용하는 이 함수는  
기본으로 제공한다.  

• void sha224(const unsigned char *m, unsigned int len, unsigned char *digest);  
void sha256(const unsigned char *m, unsigned int len, unsigned char *digest);  
void sha384(const unsigned char *m, unsigned int len, unsigned char *digest);  
void sha512(const unsigned char *m, unsigned int len, unsigned char *digest);  
void sha512_224(const unsigned char *m, unsigned int len, unsigned char *digest);  
void sha512_256(const unsigned char *m, unsigned int len, unsigned char *digest);  
–길이가 len바이트인 메시지m의 SHA-2 해시값을 digest에 저장한다. 이 함수군은 오픈소스로  
기본으로 제공한다.  

• int rsaes_oaep_encrypt(const void *m, size_t len, const void *label,  
const void *e, const void *n, void *c, int sha2_ndx) – 길이가 len 바이트인 메시지  
m을 공개키(e,n)으로 암호화한 결과를 c에 저장한다. label은 데이터를 식별하기 위한 라벨문자  
열로 NULL을 입력하여 생략할 수 있다. sha2_ndx는 사용할 SHA-2해시함수색인값으로 SHA224,  
SHA256, SHA384, SHA512, SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE  
와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.  

• int rsaes_oaep_decrypt(void *m, size_t *len, const void *label,  
const void *d, const void *n, const void *c, int sha2_ndx) –암호문 c를 개인키(d,n)  
을 사용하여 원본 메시지m과 길이len을 회복한다. label과 sha2_ndx는 암호화할 때 사용한 것과  
일치해야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.  

• int rsassa_pss_sign(const void *m, size_t len, const void *d, const void *n,  
void *s) – 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다. s  
의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.  

• int rsassa_pss_verify(const void *m, size_t len, const void *e,  
const void *n, const void *s) – 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지  
공개키 (e,n)으로 검증한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.  
