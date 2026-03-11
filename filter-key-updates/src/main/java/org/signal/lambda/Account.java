/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.signal.lambda;

import com.amazonaws.services.lambda.runtime.events.models.dynamodb.AttributeValue;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

record Account(
    byte[] aci,
    byte[] aciIdentityKey) {

  @VisibleForTesting
  static final String KEY_ACCOUNT_UUID = "U";
  @VisibleForTesting
  static final String ATTR_ACCOUNT_DATA = "D";

  @Override
  public boolean equals(final Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    Account account = (Account) o;
    return Arrays.equals(aci, account.aci) &&
        Arrays.equals(aciIdentityKey, account.aciIdentityKey);
  }

  public record Pair(@Nullable Account prev, @Nullable Account next) implements KinesisRecord<Account> {

    /** Return a partition key used by Kinesis to group distributed updates.
     *
     * @return a string that Kinesis uses to group distributed updates.  If two Pairs have the same key,
     * their updates will go into the same kinesis shard, so their ordering will be maintained.  We simply
     * make the partition key reliant on the ACI, such that updates to the same account (and thus the same ACI)
     * are ordered.  Updates to different ACIs may go to different shards in the case where our Kinesis output
     * is sharded, and ordering across shards cannot be guaranteed.
     */
    public String partitionKey() {
      final byte[] aci = prev != null ? prev.aci : next.aci;
      return HexFormat.of().formatHex(aci, 0, 4);
    }
  }

  /** Private class used to parse the dynamodb 'D' field containing a base64 encoded JSON with account data in it. */
  private record AccountData(String identityKey) { }

  private static final ObjectMapper objectMapper = new ObjectMapper()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,false);

  static Account fromItem(Map<String, AttributeValue> item) {
    Preconditions.checkNotNull(item.get(KEY_ACCOUNT_UUID));
    Preconditions.checkNotNull(item.get(ATTR_ACCOUNT_DATA));
    final byte[] uuid = new byte[16];
    item.get(KEY_ACCOUNT_UUID).getB().get(uuid);
    final ByteBuffer data = item.get(ATTR_ACCOUNT_DATA).getB().asReadOnlyBuffer();
    final byte[] identityKey;
    try {
      identityKey = Base64.getDecoder()
          .decode(objectMapper.readValue(new ByteBufferInputStream(data), AccountData.class).identityKey);
    } catch (IOException e) {
      throw new UncheckedIOException("IOException from reading bytes array", e);
    }

    return new Account(uuid, identityKey);
  }
}
