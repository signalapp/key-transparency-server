package org.signal.lambda;

import com.amazonaws.services.lambda.runtime.events.models.dynamodb.AttributeValue;
import java.nio.ByteBuffer;
import java.util.Base64;

public class Util {
  static byte[] checkLengthAndExtractBytes(final AttributeValue av, final String fieldName, int expectedLength) {
    final ByteBuffer buf = av.getB();
    final int actualLength = buf.remaining();
    if (actualLength != expectedLength) {
      throw new IllegalStateException("%s must be %d bytes, got %d. Value: %s".formatted(
          fieldName, expectedLength, actualLength, Base64.getEncoder().encodeToString(buf.array())));
    }
    final byte[] bytes = new byte[expectedLength];
    buf.get(bytes);
    return bytes;
  }
}
