/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.signal.lambda;

import com.amazonaws.services.lambda.runtime.events.models.dynamodb.AttributeValue;
import com.google.common.annotations.VisibleForTesting;
import software.amazon.awssdk.services.kinesis.KinesisClient;

import javax.annotation.Nullable;
import java.util.Map;

/**
 * Filters DynamoDb account updates for the subset relevant to key transparency, outputting them to Kinesis
 */
public class FilterAciUpdatesHandler extends AbstractUpdatesHandler<Account> {

  public FilterAciUpdatesHandler() {
    super();
  }

  @VisibleForTesting
  FilterAciUpdatesHandler(final KinesisClient kinesisClient, final String kinesisOutputStream) {
    super(kinesisClient, kinesisOutputStream);
  }

  Account fromDynamoDbImage(final Map<String, AttributeValue> image) {
    return Account.fromItem(image);
  }

  KinesisRecord<Account> toKinesisRecord(final @Nullable Account prev, final @Nullable Account next) {
    return new Account.Pair(prev, next);
  }
}
