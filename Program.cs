using System.Text;


class ECDSA
{
    //static BigInteger p = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663", System.Globalization.NumberStyles.HexNumber);
    //static BigInteger a = BigInteger.Parse("0", System.Globalization.NumberStyles.HexNumber);
    //static BigInteger b = BigInteger.Parse("7", System.Globalization.NumberStyles.HexNumber);
    //static BigInteger n = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337", System.Globalization.NumberStyles.HexNumber);
    //static BigInteger Gx = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240", System.Globalization.NumberStyles.HexNumber);
    //static BigInteger Gy = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424", System.Globalization.NumberStyles.HexNumber);

    //static BigInteger p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10);
    //static BigInteger a = new BigInteger("0", 10);
    //static BigInteger b = new BigInteger("7", 10);
    //static BigInteger n = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10);
    //static BigInteger Gx = new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240", 10);
    //static BigInteger Gy = new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424", 10);

    static BigInteger p = new BigInteger("6277101735386680763835789423207666416083908700390324961279", 10);
    static BigInteger a = new BigInteger("-3", 10);
    static BigInteger b = new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16);
    static byte[] xG = FromHexStringToByte("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
    static BigInteger n = new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16);

    static EllipticCurvePoints G = GDecompression();

    static BigInteger GeneratePrivateKey(int BitSize)
    {
        BigInteger d = new BigInteger();
        do
        {
            d.genRandomBits(BitSize, new Random());
        } while ((d < 0) || (d > n));
        return d;
    }

    public static EllipticCurvePoints GeneratePublicKey(BigInteger privateKey)
    {
        EllipticCurvePoints publicKey = EllipticCurvePoints.multiply(privateKey, G);
        return publicKey;
    }

    static (BigInteger, BigInteger) SignMessage(BigInteger privateKey, string message)
    {
        BigInteger h = new BigInteger(Encoding.Default.GetBytes(message));
        BigInteger e = h % n, k = new BigInteger(), r, s;
        EllipticCurvePoints C = new EllipticCurvePoints();
        do
        {
            do
            {
                k.genRandomBits(n.bitCount(), new Random());
            } while ((k < 0) || (k > n));
            C = EllipticCurvePoints.multiply(k, G);
            r = C.x % n;
            s = ((r * privateKey) + (k * e)) % n;
        } while ((r == 0) || (s == 0));
        return (r,s);
    }

    static bool VerifySignature(EllipticCurvePoints publicKey, string message, BigInteger r, BigInteger s)
    {
        if ((r < 1) || (r > (n - 1)) || (s < 1) || (s > (n - 1)))
            return false;

        BigInteger h = new BigInteger(Encoding.Default.GetBytes(message));
        BigInteger e = h % n;

        BigInteger v = e.modInverse(n);
        BigInteger z1 = (s * v) % n;
        BigInteger z2 = n + ((-(r * v)) % n);
        G = GDecompression();
        EllipticCurvePoints A = EllipticCurvePoints.multiply(z1, G);
        EllipticCurvePoints B = EllipticCurvePoints.multiply(z2, publicKey);
        EllipticCurvePoints C = A + B;
        BigInteger R = C.x % n;
        if (R == r)
            return true;
        else
            return false;
    }

    #region Вспомогательные функции для элептического поля
    private static EllipticCurvePoints GDecompression()
    {
        byte y = xG[0];
        byte[] x = new byte[xG.Length - 1];
        Array.Copy(xG, 1, x, 0, xG.Length - 1);
        BigInteger Xcord = new BigInteger(x);
        BigInteger temp = (Xcord * Xcord * Xcord + a * Xcord + b) % p;
        BigInteger beta = ModSqrt(temp, p);
        BigInteger Ycord = new BigInteger();
        if ((beta % 2) == (y % 2))
            Ycord = beta;
        else
            Ycord = p - beta;
        EllipticCurvePoints G1 = new EllipticCurvePoints();
        G1.a = a;
        G1.b = b;
        G1.p = p;
        G1.x = Xcord;
        G1.y = Ycord;
        G = G1;
        return G1;
    }
    public static string padding(string input, int size)
    {
        if (input.Length < size)
        {
            do
            {
                input = "0" + input;
            } while (input.Length < size);
        }
        return input;
    }
    public static BigInteger ModSqrt(BigInteger a, BigInteger q)
    {
        BigInteger b = new BigInteger();
        do
        {
            b.genRandomBits(255, new Random());
        } while (Legendre(b, q) == 1);
        BigInteger s = 0;
        BigInteger t = q - 1;
        while ((t & 1) != 1)
        {
            s++;
            t = t >> 1;
        }
        BigInteger InvA = a.modInverse(q);
        BigInteger c = b.modPow(t, q);
        BigInteger r = a.modPow(((t + 1) / 2), q);
        BigInteger d = new BigInteger();
        for (int i = 1; i < s; i++)
        {
            BigInteger temp = 2;
            temp = temp.modPow((s - i - 1), q);
            d = (r.modPow(2, q) * InvA).modPow(temp, q);
            if (d == (q - 1))
                r = (r * c) % q;
            c = c.modPow(2, q);
        }
        return r;
    }
    public static BigInteger Legendre(BigInteger a, BigInteger q)
    {
        return a.modPow((q - 1) / 2, q);
    }
    public static byte[] FromHexStringToByte(string input)
    {
        byte[] data = new byte[input.Length / 2];
        string HexByte = "";
        for (int i = 0; i < data.Length; i++)
        {
            HexByte = input.Substring(i * 2, 2);
            data[i] = Convert.ToByte(HexByte, 16);
        }
        return data;
    }
    #endregion

    public static void Main()
    {
        BigInteger privateKey = GeneratePrivateKey(192);

        EllipticCurvePoints publicKey = GeneratePublicKey(privateKey);

        Console.WriteLine("privateKey = " + privateKey);
        Console.WriteLine("publicKey = " + publicKey.x+" "+publicKey.y);

        string original = "Hello мир 123";

        Console.WriteLine("\nИсходный текст = "+original);

        (BigInteger r,BigInteger s) = SignMessage(privateKey, original);

        bool flag = VerifySignature(publicKey, original, r, s);

        Console.WriteLine("Подпись для сообщения : " + flag + "\n");

        string noriginal = "Hello, my name Ilya!";

        Console.WriteLine("Другой текст = " + noriginal);

        bool flag1 = VerifySignature(publicKey, noriginal, r, s);

        Console.WriteLine("Подпись для сообщения : " + flag1);


        Console.ReadKey();
    }


}

public class EllipticCurvePoints
{
    public BigInteger x;
    public BigInteger y;
    public BigInteger a;
    public BigInteger b;
    public BigInteger p;

    public EllipticCurvePoints()
    {
        x = new BigInteger();
        y = new BigInteger();
        a = new BigInteger();
        b = new BigInteger();
        p = new BigInteger();
    }
 
    public static EllipticCurvePoints operator +(EllipticCurvePoints p1, EllipticCurvePoints p2)
    {
        EllipticCurvePoints p3 = new EllipticCurvePoints();
        p3.a = p1.a;
        p3.b = p1.b;
        p3.p = p1.p;

        BigInteger dy = p2.y - p1.y;
        BigInteger dx = p2.x - p1.x;

        if (dx < 0)
            dx += p1.p;
        if (dy < 0)
            dy += p1.p;

        BigInteger m = (dy * dx.modInverse(p1.p)) % p1.p;
        if (m < 0)
            m += p1.p;
        p3.x = (m * m - p1.x - p2.x) % p1.p;
        p3.y = (m * (p1.x - p3.x) - p1.y) % p1.p;
        if (p3.x < 0)
            p3.x += p1.p;
        if (p3.y < 0)
            p3.y += p1.p;
        return p3;
    }
    public static EllipticCurvePoints Double(EllipticCurvePoints p)
    {
        EllipticCurvePoints p2 = new EllipticCurvePoints();
        p2.a = p.a;
        p2.b = p.b;
        p2.p = p.p;

        BigInteger dy = 3 * p.x * p.x + p.a;
        BigInteger dx = 2 * p.y;

        if (dx < 0)
            dx += p.p;
        if (dy < 0)
            dy += p.p;

        BigInteger m = (dy * dx.modInverse(p.p)) % p.p;
        p2.x = (m * m - p.x - p.x) % p.p;
        p2.y = (m * (p.x - p2.x) - p.y) % p.p;
        if (p2.x < 0)
            p2.x += p.p;
        if (p2.y < 0)
            p2.y += p.p;

        return p2;
    }

    public static EllipticCurvePoints multiply(BigInteger x, EllipticCurvePoints p)
    {
        EllipticCurvePoints temp = p;
        x = x - 1;
        while (x != 0)
        {

            if ((x % 2) != 0)
            {
                if ((temp.x == p.x) || (temp.y == p.y))
                    temp = Double(temp);
                else
                    temp = temp + p;
                x = x - 1;
            }
            x = x / 2;
            p = Double(p);
        }
        return temp;
    }
}
