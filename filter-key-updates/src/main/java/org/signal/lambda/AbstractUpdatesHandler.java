/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.amazonaws.services.lambda.runtime.events.StreamsEventResponse;
import com.amazonaws.services.lambda.runtime.events.StreamsEventResponse.BatchItemFailure;
import com.amazonaws.services.lambda.runtime.events.models.dynamodb.AttributeValue;
import com.amazonaws.services.lambda.runtime.events.models.dynamodb.StreamRecord;
import com.amazonaws.services.lambda.runtime.logging.LogLevel;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.model.PutRecordRequest;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public abstract class AbstractUpdatesHandler<T> implements
    RequestHandler<DynamodbEvent, StreamsEventResponse> {
  private static final String KINESIS_OUTPUT_STREAM_ENVIRONMENT_VARIABLE = "KINESIS_OUTPUT_STREAM";
  private static final String KINESIS_OUTPUT_REGION_ENVIRONMENT_VARIABLE = "KINESIS_OUTPUT_REGION";

  @VisibleForTesting
  static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private final KinesisClient kinesisClient;
  private final String kinesisOutputStream;

  public AbstractUpdatesHandler() {
    this(KinesisClient.builder()
            .region(Region.of(System.getenv(KINESIS_OUTPUT_REGION_ENVIRONMENT_VARIABLE)))
            .build(),
        System.getenv(KINESIS_OUTPUT_STREAM_ENVIRONMENT_VARIABLE));
  }

  @VisibleForTesting
  AbstractUpdatesHandler(final KinesisClient kinesisClient, final String kinesisOutputStream) {
    this.kinesisClient = kinesisClient;
    this.kinesisOutputStream = kinesisOutputStream;
  }

  // https://docs.aws.amazon.com/lambda/latest/dg/with-ddb-create-package.html
  @Override
  public StreamsEventResponse handleRequest(final DynamodbEvent dbUpdate, final Context context) {
    LambdaLogger logger = context.getLogger();
    List<BatchItemFailure> batchItemFailures = new ArrayList<>();
    String curRecordSequenceNumber = "";

    for (DynamodbEvent.DynamodbStreamRecord record : dbUpdate.getRecords()) {
      StreamRecord dbRecord = record.getDynamodb();
      curRecordSequenceNumber = dbRecord.getSequenceNumber();
      try {
        processRecord(dbRecord);
      } catch (Exception e) {
        batchItemFailures.add(new StreamsEventResponse.BatchItemFailure(curRecordSequenceNumber));
        logger.log(e.getMessage(), LogLevel.ERROR);
      }
    }

    return new StreamsEventResponse(batchItemFailures);
  }

  // Modeled after https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds_gettingstarted.html
  @VisibleForTesting
  void processRecord(final StreamRecord dbRecord) throws IOException {
    KinesisRecord<T> update = dbUpdateFor(dbRecord);
    if (update == null) return;
    kinesisClient.putRecord(PutRecordRequest
        .builder()
        .data(SdkBytes.fromByteArray(OBJECT_MAPPER.writeValueAsBytes(update)))
        .partitionKey(update.partitionKey())
        .streamName(kinesisOutputStream)
        .build());
  }

  @Nullable
  private KinesisRecord<T> dbUpdateFor(final StreamRecord dbRecord) {
    Map<String, AttributeValue> oldImage = dbRecord.getOldImage();
    Map<String, AttributeValue> newImage = dbRecord.getNewImage();

    final T prev = oldImage == null || oldImage.isEmpty() ? null : fromDynamoDbImage(oldImage);
    final T next = newImage == null || newImage.isEmpty() ? null : fromDynamoDbImage(newImage);

    if (prev == null && next == null) {
      return null;
    }

    if (prev != null && prev.equals(next)) {
      return null;
    }

    return toKinesisRecord(prev, next);
  }

  @Nullable
  abstract T fromDynamoDbImage(Map<String, AttributeValue> image);
  abstract KinesisRecord<T> toKinesisRecord(@Nullable T prev, @Nullable T next);
}
