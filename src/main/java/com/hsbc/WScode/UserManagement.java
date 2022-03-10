package com.hsbc.WScode;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Timestamp;
import java.util.*;

import com.hsbc.WScode.StringEncryption;

public class UserManagement {

    private static HashMap<String, String> m_user_password= new HashMap<String, String>();
    private static HashMap<String, HashSet<String>> m_role_user = new HashMap<String, HashSet<String>>(); // an username can correspond to multiple roles
    private static HashSet<String> m_role = new HashSet<>();
    private static HashMap<String, String> m_token_user = new HashMap<>(); // stores the token-user pair, search for token and return user
    private static HashMap<String, String> m_user_token = new HashMap<>(); // to aid in keeping the most recent token, sacrifice space for search speed
    private static SecretKey m_AESkey;
    private static boolean m_is_key_set = false;
    private static IvParameterSpec m_iv;
    private static boolean m_is_iv_set = false;
    private static final double TOKEN_VALID_TIME = 60*60*2; // The number of seconds for which token is valid
    private static final String TOKEN_SEPARATOR = ":-:";

    /**
     * This function will create a user and store in the user-password hashmap
     * @param user_name
     * @param password
     * @return
     */
    public static boolean createUser(String user_name, String password) {
        System.out.println("A new user has been created.");
        // check if user exists, if user exists, then add user and password
        if (m_user_password.containsKey(user_name)) {
            // if the same user name exists, return false
            return false;
        } else {
            m_user_password.put(user_name, password);
            return true;
        }
    }

    /**
     * This function will identify if user exists in user-password hashmap, if exsit,
     * @param user_name
     * @return
     */
    public static boolean deleteUser(String user_name) {
        if (m_user_password.containsKey(user_name)) {
            m_user_password.remove(user_name);
            return true;
        } else {
            return false;
        }
    }
    //    public static boolean create
    public static boolean createRole(String role) {
        if (m_role.contains(role) == true) {
            return false;
        } else {
            m_role.add(role);
            return true;
        }

    }
    public static boolean deleteRole(String role) {
        if (m_role.contains(role) == false) {
            System.out.println("The role is not in the list, will not perform insertion");
            return false;
        } else {
            m_role.remove(role);
            // if a role is deleted, then roles in the user-role pair should be removed as well
            m_role_user.remove(role);
            return true;
        }
    }

    public static boolean assignRole2User(String user, String role) {
        // need to first check if user exists
        if (m_user_password.containsKey(user) == false) {
            System.out.println("Cannot assign user to role, need to create user first");
            return false;
        } else {
            // check if the role is a valid role
            if (m_role.contains(role) == true) {
                m_role_user.get(role).add(user); // add user to the role TODO: need to check get and add
                return true;
            } else {
                System.out.println("Role is not created yet. Create role first then user can be assigned.");
                return false;
            }

        }
    }

    /**
     *
     * @param username
     * @param password
     * @return the encryption token, which can be used to identify the user; one user can have no more than one token
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public static String authenticateUser(String username, String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // check the if the username and passwords are valid
        if (m_user_password.containsKey(username) == true) {
            if (m_user_password.get(username) != password) {
                return "ERROR: WRONG PASSWORD";
            } else {
                // generate and return token
                if (m_is_key_set == false) {
                    try {
                        Random rand = new Random();
                        int rand_num = rand.nextInt(300);
                        m_AESkey = StringEncryption.generateKey(rand_num);
                        m_is_key_set = true;
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
                if (m_is_iv_set == false) {
                    m_iv = StringEncryption.generateIv();
                    m_is_iv_set = true;
                }
                if (m_user_token.containsKey(username) == true) {
                    m_token_user.remove(m_user_token.get(username));
                    m_user_token.remove(username);
                }
                long cur_time = System.currentTimeMillis() / 1000l;
                String cur_times = Long.toString(cur_time);
                // the token consists of the username and the current time, user ensures uniqueness of the encryption string
                String token = StringEncryption.encrypt("AES/CBC/PKCS5Padding", username + TOKEN_SEPARATOR + cur_times, m_AESkey, m_iv);
                // save the token and return the current toke
                m_user_token.put(username, token);
                m_token_user.put(token, username);
                return token;
            }
        } else {
            return "ERROR: USER NOT CREATED";
        }

    }

    public static void invalidateToken(String token) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // FIXME: should check if the token passed in is valid
        if (m_token_user.containsKey(token) == true) {
            // removes the token from the map
            m_user_token.remove(m_token_user.get(token));
            m_token_user.remove(token);
        } else {
            System.out.println("ERROR: TOKEN NOT STORED, INVALID TOKEN");
        }
    }

    public static boolean checkRole(String token, String role) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (m_token_user.containsKey(token) == false) {
            System.out.println("ERROR: NOT A VALID KEY");
            return false;
        } else {
            String decrypted_token = StringEncryption.decrypt("AES/CBC/PKCS5Padding", token, m_AESkey, m_iv);
            // Compare the time signature to the current time
            String elapsed_time_s = decrypted_token.substring(decrypted_token.indexOf(TOKEN_SEPARATOR + 3)); // String after token_separator is the system time in seconds
            Long elapsed_time_l = Long.parseLong(elapsed_time_s);
            Long cur_time_l = System.currentTimeMillis() / 1000l;
            if (cur_time_l - elapsed_time_l >= TOKEN_VALID_TIME) { // token expired, remove expired token, every user can only has 1 token
                System.out.println("ERROR: TOKEN EXPIRED. REQUEST NEW TOKEN AND RETRY.");
                m_user_token.remove(m_token_user.get(token));
                m_token_user.remove(token);
                return false;
            } else { // token valid, check if user is in role
                String user = m_token_user.get(token);
                if (m_role_user.get(role).contains(user) == true) {
                    System.out.println("The user has the role of : " + role);
                    return true;
                } else {
                    return false;
                }
            }
        }
    }

    /**
     *
     * @param token
     * @return returns the list containing all roles the token user belongs to, the list will be empty if the
     */
    public static ArrayList<String> checkAllRoles(String token) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ArrayList<String> all_roles = new ArrayList<>();
        if (m_token_user.containsKey(token) == false) {
            System.out.println("ERROR: NOT A VALID KEY");
            return all_roles;
        } else {
            String decrypted_token = StringEncryption.decrypt("AES/CBC/PKCS5Padding", token, m_AESkey, m_iv);
            // Compare the time signature to the current time
            String elapsed_time_s = decrypted_token.substring(decrypted_token.indexOf(TOKEN_SEPARATOR + 3)); // String after token_separator is the system time in seconds
            Long elapsed_time_l = Long.parseLong(elapsed_time_s);
            Long cur_time_l = System.currentTimeMillis() / 1000l;
            if (cur_time_l - elapsed_time_l >= TOKEN_VALID_TIME) { // token expired, remove expired token
                System.out.println("ERROR: TOKEN EXPIRED. REQUEST NEW TOKEN AND RETRY.");
                m_user_token.remove(m_token_user.get(token));
                m_token_user.remove(token);
                return all_roles;
            } else {
                // Iterator through all roles and check if the corresponding token user belongs to the role
                String user = m_token_user.get(token);
                Iterator<HashMap.Entry<String, HashSet<String>>> it = m_role_user.entrySet().iterator();
                while(it.hasNext()) {
                    HashMap.Entry<String, HashSet<String>> pair = it.next();
                    if (pair.getValue().contains("user") == true) {
                        all_roles.add(pair.getKey());
                    }
                }
                return all_roles;
            }

        }


    }

}
