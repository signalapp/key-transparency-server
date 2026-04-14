/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.lambda;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.amazonaws.services.lambda.runtime.events.StreamsEventResponse;
import com.amazonaws.services.lambda.runtime.tests.EventLoader;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.model.PutRecordRequest;

// Modeled after https://aws.amazon.com/blogs/opensource/testing-aws-lambda-functions-written-in-java/
class FilterE164UpdatesHandlerTest {
  private static byte[] b64(String b) {
    return Base64.getDecoder().decode(b);
  }

  static final byte[] PREV_ACI = b64("IiIiIiIiIiIiIiIiIiIiIg==");
  static final byte[] NEXT_ACI = b64("BbBbBbBbBbBbBbBbBbBbBg==");
  static final String NUM = "+12345678901";

  @ParameterizedTest
  @MethodSource
  void handleRequest(final String filename, final E164Constraint.Pair expected) {
    final DynamodbEvent event = EventLoader.loadDynamoDbEvent(filename);
    KinesisClient mockClient = mock(KinesisClient.class);
    FilterE164UpdatesHandler handler = new FilterE164UpdatesHandler(mockClient, "mystream");
    Context contextMock = mock(Context.class);
    final StreamsEventResponse streamsEventResponse = handler.handleRequest(event, contextMock);
    assertNull(streamsEventResponse.getBatchItemFailures());
    ArgumentCaptor<PutRecordRequest> captor = ArgumentCaptor.forClass(PutRecordRequest.class);
    verify(mockClient, times(expected == null ? 0 : 1)).putRecord(captor.capture());
    if (expected != null) {
      List<E164Constraint.Pair> e164Pairs = captor.getAllValues().stream().map(c -> mapWithoutException(c.data())).toList();
      assertEquals(expected, e164Pairs.get(0));
    }
  }

  private static Stream<Arguments> handleRequest() {
    return Stream.of(
        Arguments.of(
            "e164/testevent_creation.json",
            new E164Constraint.Pair(
                null,
                new E164Constraint(NUM, PREV_ACI))),
        Arguments.of(
            "e164/testevent_deletion.json",
            new E164Constraint.Pair(
                new E164Constraint(NUM, PREV_ACI),
                null)),
        Arguments.of(
            "e164/testevent_nochange.json", null),
        Arguments.of(
            "e164/testevent_modify.json",
            new E164Constraint.Pair(
                new E164Constraint(NUM, PREV_ACI),
                new E164Constraint(NUM, NEXT_ACI))));
  }

  E164Constraint.Pair mapWithoutException(SdkBytes in) {
    try {
      return FilterE164UpdatesHandler.OBJECT_MAPPER.readValue(in.asInputStream(), E164Constraint.Pair.class);
    } catch (IOException e) {
      throw new RuntimeException("mapping", e);
    }
  }
}
