package main

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type fakeSQSSender struct {
	input *sqs.SendMessageInput
}

func (f *fakeSQSSender) SendMessage(_ context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.input = input
	return &sqs.SendMessageOutput{}, nil
}

func TestSQSFIFOAuditStreamPreservesCanonicalIDAndTenantGroup(t *testing.T) {
	sender := &fakeSQSSender{}
	stream := &sqsFIFOAuditStream{queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/authclaw-audit.fifo", client: sender}

	err := stream.PublishEvent(testAuditEvent("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "req", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "allow"))

	if err != nil {
		t.Fatal(err)
	}
	if *sender.input.MessageGroupId != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("unexpected message group: %s", *sender.input.MessageGroupId)
	}
	if *sender.input.MessageDeduplicationId != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
		t.Fatalf("unexpected deduplication id: %s", *sender.input.MessageDeduplicationId)
	}
}

func TestSQSFIFOAuditStreamRejectsMissingOrInvalidCanonicalID(t *testing.T) {
	stream := &sqsFIFOAuditStream{queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/authclaw-audit.fifo", client: &fakeSQSSender{}}

	if err := stream.PublishEvent(testAuditEvent("", "req", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "allow")); err == nil || !strings.Contains(err.Error(), "audit_record_id") {
		t.Fatalf("expected missing audit_record_id failure, got %v", err)
	}
	if err := stream.PublishEvent(testAuditEvent("not-a-uuid", "req", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "allow")); err == nil || !strings.Contains(err.Error(), "canonical UUID") {
		t.Fatalf("expected canonical UUID failure, got %v", err)
	}
}
