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
import static org.mockito.Mockito.when;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.amazonaws.services.lambda.runtime.events.StreamsEventResponse;
import com.amazonaws.services.lambda.runtime.tests.EventLoader;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.model.PutRecordRequest;

// Modeled after https://aws.amazon.com/blogs/opensource/testing-aws-lambda-functions-written-in-java/
class FilterUsernameUpdatesHandlerTest {
  private static byte[] b64(String b) {
    return Base64.getDecoder().decode(b);
  }

  static final byte[] PREV_ACI = b64("IiIiIiIiIiIiIiIiIiIiIg==");
  static final byte[] NEXT_ACI = b64("BbBbBbBbBbBbBbBbBbBbBg==");
  static final byte[] USERNAME_HASH = b64("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=");;

  @ParameterizedTest
  @MethodSource
  void handleRequest(final String filename, final UsernameConstraint.Pair expected) {
    final DynamodbEvent event = EventLoader.loadDynamoDbEvent(filename);
    KinesisClient mockClient = mock(KinesisClient.class);
    FilterUsernameUpdatesHandler handler = new FilterUsernameUpdatesHandler(mockClient, "mystream");
    Context contextMock = mock(Context.class);
    final StreamsEventResponse streamsEventResponse = handler.handleRequest(event, contextMock);
    assertNull(streamsEventResponse.getBatchItemFailures());
    ArgumentCaptor<PutRecordRequest> captor = ArgumentCaptor.forClass(PutRecordRequest.class);
    verify(mockClient, times(expected == null ? 0 : 1)).putRecord(captor.capture());
    if (expected != null) {
      List<UsernameConstraint.Pair> usernamePairs = captor.getAllValues().stream().map(c -> mapWithoutException(c.data())).toList();
      assertEquals(expected, usernamePairs.get(0));
    }
  }

  private static Stream<Arguments> handleRequest() {
    return Stream.of(
        Arguments.of(
            "username/testevent_account_deletion.json", new UsernameConstraint.Pair(
                new UsernameConstraint(USERNAME_HASH, PREV_ACI, true),
                null)),
        Arguments.of(
            "username/testevent_create_confirm.json", new UsernameConstraint.Pair(
                null,
                new UsernameConstraint(USERNAME_HASH, NEXT_ACI, true))),
        Arguments.of(
            "username/testevent_create_reserve.json", null),
        Arguments.of(
            "username/testevent_deletion_hold_expiring.json", null),
        Arguments.of(
            "username/testevent_modify_confirm.json",
            new UsernameConstraint.Pair(
                null,
                new UsernameConstraint(USERNAME_HASH, NEXT_ACI, true))),
        Arguments.of(
            "username/testevent_modify_unconfirm.json",
            new UsernameConstraint.Pair(
                new UsernameConstraint(USERNAME_HASH, PREV_ACI, true),
                null)),
        Arguments.of(
            "username/testevent_modify_aci_changed_old_confirmed_new_confirmed.json",
            new UsernameConstraint.Pair(
                new UsernameConstraint(USERNAME_HASH, PREV_ACI, true),
                new UsernameConstraint(USERNAME_HASH, NEXT_ACI, true))),
        Arguments.of(
            "username/testevent_modify_aci_changed_old_unconfirmed_new_confirmed.json",
            new UsernameConstraint.Pair(
                null,
                new UsernameConstraint(USERNAME_HASH, NEXT_ACI, true))),
        Arguments.of(
            "username/testevent_modify_aci_changed_old_confirmed_new_unconfirmed.json",
            new UsernameConstraint.Pair(
                new UsernameConstraint(USERNAME_HASH, PREV_ACI, true),
                null)),
        Arguments.of(
            "username/testevent_nochange.json", null));
  }

  UsernameConstraint.Pair mapWithoutException(SdkBytes in) {
    try {
      return FilterE164UpdatesHandler.OBJECT_MAPPER.readValue(in.asInputStream(), UsernameConstraint.Pair.class);
    } catch (IOException e) {
      throw new RuntimeException("mapping", e);
    }
  }

  @Test
  void invalidUsernameHashLength() {
    final String fileName = "username/testevent_multiple_records_first_one_invalid.json";
    final DynamodbEvent event = EventLoader.loadDynamoDbEvent(fileName);

    KinesisClient mockClient = mock(KinesisClient.class);
    FilterUsernameUpdatesHandler handler = new FilterUsernameUpdatesHandler(mockClient, "mystream");

    Context contextMock = mock(Context.class);
    when(contextMock.getLogger()).thenReturn(mock(LambdaLogger.class));
    final StreamsEventResponse streamsEventResponse = handler.handleRequest(event, contextMock);
    assertEquals(1, streamsEventResponse.getBatchItemFailures().size());
    ArgumentCaptor<PutRecordRequest> captor = ArgumentCaptor.forClass(PutRecordRequest.class);
    verify(mockClient, times(0)).putRecord(captor.capture());
  }
}
