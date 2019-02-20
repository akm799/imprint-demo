package uk.co.akm.imprintdemo.key;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public interface KeySerializerConstants {
    char SEPARATOR = '|';
    String KEY_ALGORITHM_EC = "EC";
    String KEY_ALGORITHM_RSA = "RSA";
    Set<String> KEY_ALGORITHMS = new HashSet<>(Arrays.asList(KEY_ALGORITHM_EC, KEY_ALGORITHM_RSA));
}
