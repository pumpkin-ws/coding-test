import com.hsbc.WScode.UserManagement;
import org.junit.Test;
import junit.framework.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Array;
import java.util.*;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.*;

public class UnitTest {
    @Test
    public void createDeleteUser() {
        assertTrue("assertion should fail", UserManagement.createUser("Wilson", "123456"));
        assertFalse(UserManagement.createUser("Wilson", "123456"));
        assertTrue(UserManagement.createUser("Tom", "123456"));
        assertTrue(UserManagement.createUser("Tanya", "123456"));
        assertTrue(UserManagement.createUser("Alice", "123456"));
        assertTrue(UserManagement.deleteUser("Alice"));
        assertFalse(UserManagement.deleteUser("Alice"));
    }

    @Test
    public void createDeleteRole() {
        assertTrue(UserManagement.createRole("admin"));
        assertTrue(UserManagement.createRole("visitor"));
        assertFalse(UserManagement.createRole("admin"));
        assertTrue(UserManagement.deleteRole("admin"));
        assertFalse(UserManagement.deleteRole("admin"));
        assertTrue(UserManagement.deleteRole("visitor"));
        assertFalse(UserManagement.deleteRole("abc"));
    }

    @Test
    public void addRole2User() {
        assertTrue(UserManagement.createUser("Wilson", "123456"));
        assertTrue(UserManagement.createUser("Tom", "123456"));
        assertTrue(UserManagement.createUser("Tanya", "123456"));
        assertTrue(UserManagement.createUser("Alice", "123456"));
        assertTrue(UserManagement.createRole("admin"));
        assertTrue(UserManagement.createRole("visitor"));
        assertTrue(UserManagement.assignRole2User("Wilson", "admin"));
        // Nothing happens with mutilple assignment
        assertTrue(UserManagement.assignRole2User("Wilson", "admin"));
        assertTrue(UserManagement.assignRole2User("Wilson", "admin"));
        assertTrue(UserManagement.assignRole2User("Wilson", "visitor"));
        assertTrue(UserManagement.assignRole2User("Tanya", "visitor"));
        assertTrue(UserManagement.assignRole2User("Tom", "admin"));
        assertFalse(UserManagement.assignRole2User("Jason", "admin"));
        assertFalse(UserManagement.assignRole2User("Jason", "admin"));

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
