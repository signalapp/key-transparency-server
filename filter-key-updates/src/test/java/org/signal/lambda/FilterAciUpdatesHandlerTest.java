/*
 * Copyright 2022 Signal Messenger, LLC
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
class FilterAciUpdatesHandlerTest {

  private static byte[] b64(String b) {
    return Base64.getDecoder().decode(b);
  }

  static final byte[] PREV_ACI = b64("IiIiIiIiIiIiIiIiIiIiIg==");
  static final byte[] PREV_ACI_KEY = b64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  static final byte[] NEXT_ACI_KEY = b64("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");

  @ParameterizedTest
  @MethodSource
  void handleRequest(final String filename, final Account.Pair expected) {
    final DynamodbEvent event = EventLoader.loadDynamoDbEvent(filename);
    KinesisClient mockClient = mock(KinesisClient.class);
    FilterAciUpdatesHandler handler = new FilterAciUpdatesHandler(mockClient, "mystream");
    Context contextMock = mock(Context.class);
    final StreamsEventResponse streamsEventResponse = handler.handleRequest(event, contextMock);
    assertNull(streamsEventResponse.getBatchItemFailures());
    ArgumentCaptor<PutRecordRequest> captor = ArgumentCaptor.forClass(PutRecordRequest.class);
    verify(mockClient, times(expected == null ? 0 : 1)).putRecord(captor.capture());
    if (expected != null) {
      List<Account.Pair> accounts = captor.getAllValues().stream().map(c -> mapWithoutException(c.data())).toList();
      assertEquals(expected, accounts.get(0));
    }
  }

  private static Stream<Arguments> handleRequest() {
    return Stream.of(
        Arguments.of(
            "aci/testevent_deletion.json",
            new Account.Pair(
                new Account(PREV_ACI, PREV_ACI_KEY),
                null)),
        Arguments.of(
            "aci/testevent_nochange.json", null),
        Arguments.of(
            "aci/testevent_registration1.json",
            new Account.Pair(
                null,
                new Account(PREV_ACI, PREV_ACI_KEY))),
        Arguments.of(
            "aci/testevent_registration2.json",
            new Account.Pair(
                new Account(PREV_ACI, PREV_ACI_KEY),
                new Account(PREV_ACI, NEXT_ACI_KEY))));
  }

  Account.Pair mapWithoutException(SdkBytes in) {
    try {
      return FilterAciUpdatesHandler.OBJECT_MAPPER.readValue(in.asInputStream(), Account.Pair.class);
    } catch (IOException e) {
      throw new RuntimeException("mapping", e);
    }
  }
}
