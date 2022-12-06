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
