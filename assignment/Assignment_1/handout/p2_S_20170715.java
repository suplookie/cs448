import java.util.Scanner;

public class p2_S_20170715
{
    public static long xor;
    public static long r;
    public static String iv;
    public static String y;
    public static pad_oracle p;

    public static void main(String[] args) 
    {
        if (args.length == 0)
        {
            Scanner scanner = new Scanner(System.in);
            iv = scanner.next();
            y = scanner.next();
        }
        else
        {
            iv = args[0];
            y = args[1];            
        }
        xor = 0;
        r = 0;
        p = new pad_oracle();

        for (int i = 0; i < 8; i++)
        {
            while (!(p.doOracle(long2str(r), y) && (i == 7 || p.doOracle(long2str(r + (1L << ((i + 1) * 8))), y))))
            {
                r += (1L << (i * 8));
            }

            long padding = 0;

            for (int j = 0; j < i + 1; j++)
            {
                padding += ((long)(i + 1) << (j * 8));
            }

            xor = r ^ padding;

            for (int j = 0; j < i + 1; j++)
            {
                padding += (1L << (j * 8));
            }

            r = xor ^ padding;
        }

        long plaintext = str2long(iv)^xor;
        String text = "";

        for (int i = 0; i < 8; i++)
        {
            char a = (char)((plaintext >> (i * 8)) & ((1 << 8) - 1));
            text = Character.toString(a) + text;
        }
        
        System.out.println(text);
    }


    public static String long2str(long bytes)
    {
        String ret = "";
        for (int i = 0; i < 16; i++) 
        {
            long last4 = 15 & bytes;
            String now;
            if (last4 > 9)
            {
                now = Character.toString((char)('a' + last4 - 10));
            }
            else
            {
                now = Long.toString(last4);
            }
            ret = now + ret;
            bytes >>= 4;
        }
        ret = "0x" + ret;
        return ret;
    }

    public static long str2long(String bytes)
    {
        long ret = 0;
        for (int i = 2; i < 18; i++)
        {
            char cAt = bytes.charAt(i);
            long adder;
            if (cAt > '9')
            {
                adder = cAt - 'a' + 10;
            }
            else
            {
                adder = cAt - '0';
            }
            ret += adder << (4 * (17 - i));
        }
        return ret;
    }
}