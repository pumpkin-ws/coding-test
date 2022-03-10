import com.hsbc.WScode.UserManagement;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Array;
import java.util.*;

public class UnitTest {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {


    }

    private static void verifySomething() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HashMap<String, Integer> ages = new HashMap<>();
        ages.put("wilson", 32);
        ages.put("rose", 34);
        ages.put("wilson", 100);

        System.out.println(ages);
        for (Integer age : ages.values()) {
            age = 1;
        }
        Iterator<HashMap.Entry<String, Integer>> it = ages.entrySet().iterator();
        while(it.hasNext()) {
            Map.Entry<String, Integer> pair = it.next();
            pair.setValue(1);
        }
        System.out.print("Wilson age: " + ages.get("wilson"));

        long time = System.currentTimeMillis() / 1000l;
        String times = Long.toString(time);
        System.out.println(times);

        String encrypt_code = UserManagement.authenticateUser("ws", "din");
        System.out.println(encrypt_code);
//        UserManagement.invalidateUser(encrypt_code);

        String token = "wilson::_123";
        String time_part = token.substring(token.indexOf("::_") + 3);
        System.out.println(time_part);
        long t = Long.parseLong(time_part);
        System.out.println(t);

        Random rand = new Random();
        for (int i = 0; i < 100; i++) {
            System.out.print(rand.nextInt(300) + ", ");
        }
    }


}
