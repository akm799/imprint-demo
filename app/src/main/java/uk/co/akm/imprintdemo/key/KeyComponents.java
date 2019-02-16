package uk.co.akm.imprintdemo.key;

import java.math.BigInteger;

class KeyComponents {
    private final String SEPARATOR_INDEX = "\\|";
    private final int FIRST_INDEX = 0;
    private final int SECOND_INDEX = 1;
    private final int NUMBER_OF_PARTS = 2;

    final BigInteger first;
    final BigInteger second;

    KeyComponents(String serializedKey) {
        final String[] parts = serializedKey.split(SEPARATOR_INDEX);
        if (parts.length != NUMBER_OF_PARTS) {
            throw new KeySerializationException("Cannot deserialize key. Serilized data must comply with the format: [big_integer_1]|[big_integer_2]");
        }

        try {
            first = new BigInteger(parts[FIRST_INDEX]);
            second = new BigInteger(parts[SECOND_INDEX]);
        } catch (Exception e) {
            throw new KeySerializationException("Cannot deserialize key with component 1 '" + parts[FIRST_INDEX] + "' and component 2 '" + parts[SECOND_INDEX] + "'.");
        }
    }
}
