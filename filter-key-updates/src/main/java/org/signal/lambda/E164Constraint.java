/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.lambda;

import com.amazonaws.services.lambda.runtime.events.models.dynamodb.AttributeValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Map;

import static org.signal.lambda.Util.checkLengthAndExtractBytes;

record E164Constraint(
    String e164,
    byte[] aci) {

  @VisibleForTesting
  static final String KEY_ACCOUNT_E164 = "P";
  @VisibleForTesting
  static final String ATTR_ACCOUNT_UUID = "U";

  @Override
  public boolean equals(final Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    E164Constraint e164Constraint = (E164Constraint) o;
    return e164.equals(e164Constraint.e164) &&
        Arrays.equals(aci, e164Constraint.aci);
  }

  public record Pair(@Nullable E164Constraint prev, @Nullable E164Constraint next) implements KinesisRecord<E164Constraint> {

    /** Return a partition key used by Kinesis to group distributed updates.
     *
     * @return a string that Kinesis uses to group distributed updates. Updates to the
     * same E164 are ordered. Updates to different E164s may go to different shards in the case where our Kinesis output
     * is sharded, and ordering across shards cannot be guaranteed.
     */
    public String partitionKey() {
      return prev != null ? prev.e164 : next.e164;
    }
  }

  static E164Constraint fromItem(Map<String, AttributeValue> item) {
    Preconditions.checkNotNull(item.get(KEY_ACCOUNT_E164));
    Preconditions.checkNotNull(item.get(ATTR_ACCOUNT_UUID));

    final String number = item.get(KEY_ACCOUNT_E164).getS();

    final byte[] uuid = checkLengthAndExtractBytes(item.get(ATTR_ACCOUNT_UUID), "UUID", 16);

    return new E164Constraint(number, uuid);
  }
}
