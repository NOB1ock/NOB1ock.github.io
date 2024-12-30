# Padding Oracle Attack
Padding Oracle Attack是一种基于填充验证的攻击，针对使用对称加密模式（如 AES-CBC）和特定填充方式（如 PKCS#5/PKCS#7）的系统。如果系统对解密后的填充验证有反馈（比如提示填充错误或成功），攻击者可以利用这一反馈逐字节地恢复密文的明文内容。
## 1. CBC加密模式
在本文中，我们以CBC（Cipher-block chaining）加密模式为例。在CBC加密模式中，先将明文分成等长的若干块，然后每个明文块先与前一个密文块（经过加密的明文块）进行异或后，再加密。这种方法中，每个密文块都依赖于前面所有的明文块，而第一明文块依赖一个初始向量，该向量长度和块长度一样。由于初始向量每次是随机产生的，所以每次加密的值都会不一样。


$$
\begin{array}{l}
C_i=E_k(P_i⊕C_{i-1}) \\
C_0=IV
\end{array}
$$

![Pasted image 20241127153929.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127153929.png)
*（加密过程）*
解密则是反过来，先取出初始向量（初始向量通常放在密文头部一同发送，在密码学层面初始向量无需保密），同样将密文分成与加密时一样长度的块。将密文块进行解密，再与下一个密文块进行异或，得到明文块，最后拼接成明文。而第一个密文块解密后与初始向量异或。


$$
\begin{array}{l}
P_i=D_k(C_i)⊕C_{i-1} \\
C_0=IV
\end{array}
$$

![Pasted image 20241127154545.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127154545.png)
*（解密过程）*
但是明文长度不一定是块长的整数倍，所以需要将最后一块填充补齐。而CBC规定，缺n位填充n个0x0n，如缺两位，填充两位0x02。如果明文恰好是分组的整数倍，那么也会填充一个完整的块。

![Pasted image 20241128092601.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128092601.png)
*（块长度为8字节，填充示意）*

## 2. 攻击过程
一段密文发送给服务器的时候，会先解密，然后再校验明文的填充位是否正确，如果错误则抛出异常，如果正确则返回解密结果。

![Pasted image 20241127172641.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127172641.png)
上图是一个密文块解密的过程，有如下数据：

- 分块长度为8字节
- 密文（Cipher）：`0x7A812356D27E1FAD`
- 中间值（Intermediary Value）：`0x744BB0415063728D`
- 初始向量（Initialization Vector）：`0x1122334455667788`
- 明文（Plaintext）：`AES`+`0x0505050505`
假设现有一台服务器用于解密校验，解密成功则会返回True，填充校验失败返回Error。传给服务器的数据格式是`IV+C`（初始向量拼接上密文）。现我们仅知道密文和初始向量，那么如何才能在没有密钥的情况下破解出明文？
*（为了区分中间值和初始向量的符号表示，中间值为MV，初始向量为IV）*
1. 先假设初始向量为`0x0000000000000000`，将其与密文拼接后发送给系统，系统的解密结果如下：
	![Pasted image 20241127225537.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127225537.png)
	*（需要注意的是，中间值和明文是不可见的）*
	中间值与0异或的结果是中间值本身。对于这个结果系统返回的肯定是Error，因为块长度为8字节，那么填充字节只会是0x01到0x08之间的值。系统会先进行上面的运算，这个解密的操作不会报错，因为只是数学计算而已。但是在校验填充位的时候，明文最后一字节P\[7]的值`0x8D`不符合填充规范，所以系统会返回Error。
2. 传入初始向量，值为`0x000000000000008C`，系统解密过程如下：
    ![Pasted image 20241127225606.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127225606.png)
    同样系统解密过程不会报错，校验的时候P\[7]的值为`0x01`，符合填充规范，至于解密出的明文在业务层面是否正确，加解密算法并不关心。现在得到IV\[7]=0x8C，P\[7]=0x01
    $∵P_7=MV_7⊕IV_7$
    $∴MV_7=P_7⊕IV_7=01⊕8C=8D$
    经过以上计算，得到中间值的第7个字节的值为`0x8D`。
3. 这是在知晓MV\[7]的值时，得到IV\[7]的值是`0x8C`。从攻击的角度，在不知道中间值的情况下，得到对应的初始向量，再反推中间值。不难看出只有一个值与MV\[7]异或的结果为`0x01`，其余情况系统校验填充规则失败，所以可以爆破出P\[7]为`0x01`时，IV\[7]的值，进而计算出真正的MV\[7]的值。这便是padding oracle这种攻击方式的关键之处。
4. 在得到中间值的第8个字节的值之后，就可以爆破其第7个字节
    现在需要系统校验最后两个字节，所以填充的值为`0x02`。为了保证初始向量与中间值异或的第8个字节的值为`0x02`，计算初始向量第8个字节的值 $0x02⊕0x8D=0x8F$ 得到第二轮计算的开始的初始向量为`0x000000000000008F`，通过爆破得到IV\[6]的值为`0x70`，解密示意如下：
    ![Pasted image 20241127230507.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241127230507.png)
    $∴MV_6=P_6⊕IV_6=02⊕70=72$
    现在得到中间值为`0x************728D`
5. 每一个字节有256个值，每个字节至多爆破256次，一个8字节长的块需要爆破$2^{8×8}=2048$次。现在计算出所有的中间值，如下：
    ![Pasted image 20241128092243.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128092243.png)
    至此得到了完整的中间值`0x744BB0415063728D`，加上原本就掌握的初始向量`0x1122334455667788`
    $P=MV⊕IV$
    $P==0x744BB0415063728D⊕0x1122334455667788=0x6569830505050505$
    去除5字节的填充位，实际有效数据`0x656983`，即明文AES，最终在不知晓密钥的情况下获得了明文。
6. 这只是一个块的情况下，一般情况下肯定有多个块，但是逐字节爆破的方式是一样的，只是上面过程的初始向量换成了前一个密文块

## 3. 原理
由于块加密（分组加密）要求明文数据必须为块长的整数倍，所以需要对最后一个块进行填充以满足块长要求。解密后会检查填充位是否符合要求，如果填充不正确，则系统会返回不同的错误信息，类似于爆破账密的时候，服务器会返回“用户名不存在”、“密码错误”或“登录成功”，根据系统反馈的信息之间的差异，逐字节爆破出正确的值。所以利用这种攻击有两个前提条件：
- 拥有初始向量和密文
- 系统校验填充正确或错误的返回信息之间存在差异

## 4. 代码演示

### 4.1 Java实现
先用Java实现AES/128/CBC/PKCS5的加解密，代码如下：
```java
import org.apache.commons.codec.binary.Hex; 
import javax.crypto.Cipher;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.SecretKeySpec;  

public class AesAlgorithm {  
    private static String key = "0123456789abcdef"; 
    // 为了演示方便这里将初始向量固定，并以16进制形式展示
    private static String iv = "00112233445566778899AABBCCDDEEFF";  
    // 加密
    public static String aesEncrypt(String plaintext) throws Exception {  
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES"); 
        // 将iv转为16进制形式 
        IvParameterSpec ivSpec = new IvParameterSpec(Hex.decodeHex(iv));  
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");  
        aes.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);  
        return Hex.encodeHex(aes.doFinal(plaintext.getBytes())).toUpperCase();  
    }  
    // 解密
    public static String aesDecrypt(String ciphertext) throws Exception {  
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");  
        IvParameterSpec ivSpec = new IvParameterSpec(Hex.decodeHex(iv));  
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");  
        aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);  
        return new String(aes.doFinal(Hex.decodeHex(ciphertext)));  
    }  
    // 传入初始向量解密
    public static String aesDecrypt(String ciphertext, IvParameterSpec ivSpec) throws Exception {  
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");  
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");  
        aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);  
        return new String(aes.doFinal(Hex.decodeHex(ciphertext)));  
    }  
}
```
测试一下
```java
System.out.printf("%-5s：%s%n", "加密", aesEncrypt("AES"));  
System.out.printf("%-5s：%s%n", "解密", aesDecrypt("F6AE3048B3190AA1017F8F20A25299DE"));  
IvParameterSpec iv = new IvParameterSpec(Hex.decodeHex("00112233445566778899AABBCCDDEEFF"));  
System.out.printf("%-5s：%s%n", "IV解密", aesDecrypt("F6AE3048B3190AA1017F8F20A25299DE", iv));
```
![Pasted image 20241128112934.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128112934.png)
1. 尝试将传入的初始向量改为全0
	![Pasted image 20241128135252.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128135252.png)
	可以看到抛出了`BadPaddingException`异常，表示填充失败。尝试爆破最后一字节看是否能得到一个不抛出异常的值
	![Pasted image 20241128135635.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128135635.png)
	从遍历结果来看，找到了这样一个初始向量`0x000000000000000000000000000000F3`使得结果最后一个填充位值为`0x01`
2. 编写最终的解密代码：[PaddingOracleAttackDemo](https://github.com/AlertMouse/PaddingOracleAttackDemo/blob/master/Java/src/master/java/com/poa/PaddingOracleAttack.java)
	![Pasted image 20241128152311.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241128152311.png)
	破解出的明文
### 4.2 Python实现
[PaddingOracleAttackDemo](https://github.com/AlertMouse/PaddingOracleAttackDemo/tree/master/Python)
![Pasted image 20241203095343.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241203095343.png)



## 5. 加密任意数据

上面只是利用paddnng oracle解密数据，但在测试的时候需要将payload加密，才能与系统正常交互。那paddnng orcale能用于加密任意数据吗？试着推导一下：

∵$P[n]=D_k(C[n])⊕C[n-1]$ *（解密公式，D为解密算法，n为块序号）*

∴$MV[n]=D_k(C[n])=P[n]⊕C[n-1]$ *（MV是中间值）*

∵$P'[n]=MV[n]⊕C'[n-1]$ *（P'是要加密的明文，C'是伪造的密文）*

∴$C'[n-1]=MV[n]⊕P'[n]$

∴$C'[n-1]=P[n]⊕C[n-1]⊕P'[n]$

由上述推论可以得到第n-1个伪造的密文块可以由第n个明文块、第n-1个密文块、第n个要加密的明文块异或得到。那么只需要密文、对应的明文就可以得到要伪造的密文了吗？

根据$C'_{n-1}=P_n⊕C_{n-1}⊕P'_n$得到下面的式子：

$C'[2]=P'[3]⊕P[3]⊕C[2]$

$C'[1]=P'[2]⊕P[2]⊕C[1]$

$C'[0]=P'[1]⊕P[1]⊕C[0]$

然后得到密文：C'\[0]||C'\[1]||C'\[2]||C\[3]。然而这段密文解密后只有最后一块C\[3]解密后为期望的P'\[3]，其他都是一段无意义的数据。
![Pasted image 20241203112736.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241203112736.png)
*（按照上述推论实现的加密方法，解密的数据只有最后16字节是期望的值）*
因为：$P'[n]=C'[n-1]⊕P[n]⊕C[n-1]=C'[n-1]⊕D_k(C[n])⊕C[n-1]⊕C[n-1]=C'[n-1]⊕D_k(C[n])$

即：$P'[n]=C'[n-1]⊕D_k(C[n])$

所以有：

$P'[3]=C'[2]⊕D_k(C[3])$

$P'[2]=C'[1]⊕D_k(C[2])$

$P'[1]=C'[0]⊕D_k(C[1])$

可以看到解密依赖于伪造的前一个密文块，以及原来明文对应的密文块。但是除了最后一个密文块C\[3]，其余密文块均已被修改。即$D_k(C[n-1])$实际在系统的解密过程中是$D_k(C'[n-1])$，而$D_k(C'[n-1])$解密之后的中间值是未知的。所以解密后除了最后一个明文块是需要的数据，其余都是不可控的未知数据，因此这种方式达不到加密任意数据的目的。

$D_k(C'[n-1])$实际就是中间值，由于这个中间值未知导致了解密出来的数据不符合预期，那么有没有办法控制这个中间值或者得到这个中间值呢？回想一下上文利用padding oracle解密的时候，关键一步就是通过利用填充正确与否的提示，爆破加密块对应中间值的每一字节，得到中间值再与前一密文块异或得到对应的明文块。而我们就可以通过这个方法，获得伪造的密文块在系统解密后对应的中间值，即$D_k(C'[n-1])$的值。推导过程如下：

*（共有n个需要再加密的明文块）*

最后一个明文块：$P'[n]=C'[n-1]⊕D_k(C[n])$

得到倒数第二个密文块：$C'[n-1]=P'[n]⊕D_k(C[n])=P'[n]⊕MV[n]$

倒数第三个密文块：$C'[n-2]=P'[n-1]⊕D_k(C[n-1])=P'[n-1]⊕MV[n-1]$

此时C\[n-1]实际上已经改变为C'\[n-1]，所以倒数第三个密文块值为$C'[n-2]=P'[n-1]⊕D_k(C'[n-1])=P'[n-1]⊕MV'[n-1]$

那么可以得到以下等式：

*(n≥1)*

$C'[n]=C[n]$

$C'[n-1]=P'[n]⊕MV[n]$

$C'[n-2]=P'[n-1]⊕MV’[n-1]$

...

$C'[0]=P'[1]⊕MV'[1]$

新密文为：C'\[1]\||C'\[2]\||...\||C\[n]，初始向量为C'\[0]。

代码实现思路：

1. 先获取原密文块最后两个块，不足两个由最后初始向量充当第一个密文块
2. 通过padding oracle爆破最后一个密文块的中间值，再与要加密的最后一个明文块异或得到倒数第二个密文块
3. 再通过padding oracle爆破倒数第二个密文块的其中间值，再与上一个要加密的明文块异或得到倒数第三个密文块，如此反复直至得到每一块要加密的明文块前面一个密文块
4. 拼接所有的密文块
[PaddingOracleAttackDemo/Python/ForgePlaintext.py](https://github.com/AlertMouse/PaddingOracleAttackDemo/blob/master/Python/ForgePlaintext.py)
![Pasted image 20241203134654.png](https://raw.githubusercontent.com/nob1ock/nob1ock.github.io/refs/heads/master/_posts/_images/2024-12-30/Pasted%20image%2020241203134654.png)
