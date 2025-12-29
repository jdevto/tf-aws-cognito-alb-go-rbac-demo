package requests

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

// Request represents a request in the system
type Request struct {
	RequestID   string    `dynamodbav:"request_id" json:"request_id"`
	CreatedBy   string    `dynamodbav:"created_by" json:"created_by"`
	CreatedAt   time.Time `dynamodbav:"created_at" json:"created_at"`
	Status      string    `dynamodbav:"status" json:"status"` // pending, approved, rejected
	Description string    `dynamodbav:"description" json:"description"`
	ApprovedBy  string    `dynamodbav:"approved_by,omitempty" json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `dynamodbav:"approved_at,omitempty" json:"approved_at,omitempty"`
}

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

var (
	dynamoClient *dynamodb.Client
	tableName    string
	clientOnce   sync.Once
)

// InitDynamoClient initializes the DynamoDB client
func InitDynamoClient(ctx context.Context, table string) error {
	var initErr error
	clientOnce.Do(func() {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			initErr = fmt.Errorf("failed to load AWS config: %w", err)
			return
		}
		dynamoClient = dynamodb.NewFromConfig(cfg)
		tableName = table
	})
	return initErr
}

// CreateRequest creates a new request in DynamoDB
func CreateRequest(ctx context.Context, createdBy, description string) (*Request, error) {
	if dynamoClient == nil || tableName == "" {
		return nil, fmt.Errorf("DynamoDB client not initialized")
	}

	now := time.Now()
	request := &Request{
		RequestID:   uuid.New().String(),
		CreatedBy:   createdBy,
		CreatedAt:   now,
		Status:      StatusPending,
		Description: description,
	}

	item, err := attributevalue.MarshalMap(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	_, err = dynamoClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return request, nil
}

// ListRequests lists all requests (optionally filtered by status)
func ListRequests(ctx context.Context, statusFilter string) ([]*Request, error) {
	if dynamoClient == nil || tableName == "" {
		return nil, fmt.Errorf("DynamoDB client not initialized")
	}

	input := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}

	// If status filter is provided, add a filter expression
	if statusFilter != "" {
		input.FilterExpression = aws.String("#status = :status")
		input.ExpressionAttributeNames = map[string]string{
			"#status": "status",
		}
		input.ExpressionAttributeValues = map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: statusFilter},
		}
	}

	result, err := dynamoClient.Scan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan requests: %w", err)
	}

	var requests []*Request
	for _, item := range result.Items {
		var req Request
		if err := attributevalue.UnmarshalMap(item, &req); err != nil {
			log.Printf("⚠️  Failed to unmarshal request item: %v, skipping", err)
			continue // Skip invalid items
		}
		requests = append(requests, &req)
	}

	// Sort by created_at descending (newest first)
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].CreatedAt.After(requests[j].CreatedAt)
	})

	return requests, nil
}

// GetRequest retrieves a single request by ID
func GetRequest(ctx context.Context, requestID string) (*Request, error) {
	if dynamoClient == nil || tableName == "" {
		return nil, fmt.Errorf("DynamoDB client not initialized")
	}

	result, err := dynamoClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"request_id": &types.AttributeValueMemberS{Value: requestID},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if result.Item == nil {
		return nil, fmt.Errorf("request not found")
	}

	var request Request
	if err := attributevalue.UnmarshalMap(result.Item, &request); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	return &request, nil
}

// ApproveRequest approves a request
func ApproveRequest(ctx context.Context, requestID, approvedBy string) error {
	if dynamoClient == nil || tableName == "" {
		return fmt.Errorf("DynamoDB client not initialized")
	}

	now := time.Now()
	approvedAtAV, err := attributevalue.Marshal(now)
	if err != nil {
		return fmt.Errorf("failed to marshal approved_at: %w", err)
	}

	_, err = dynamoClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"request_id": &types.AttributeValueMemberS{Value: requestID},
		},
		UpdateExpression: aws.String("SET #status = :status, approved_by = :approved_by, approved_at = :approved_at"),
		ConditionExpression: aws.String("#status = :pending"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":      &types.AttributeValueMemberS{Value: StatusApproved},
			":approved_by": &types.AttributeValueMemberS{Value: approvedBy},
			":approved_at": approvedAtAV,
			":pending":     &types.AttributeValueMemberS{Value: StatusPending},
		},
	})

	if err != nil {
		var condCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &condCheckErr) {
			return fmt.Errorf("request is not in pending status")
		}
		return fmt.Errorf("failed to approve request: %w", err)
	}

	return nil
}

// RejectRequest rejects a request
func RejectRequest(ctx context.Context, requestID, rejectedBy string) error {
	if dynamoClient == nil || tableName == "" {
		return fmt.Errorf("DynamoDB client not initialized")
	}

	now := time.Now()
	rejectedAtAV, err := attributevalue.Marshal(now)
	if err != nil {
		log.Printf("Error marshaling rejected_at: %v", err)
		return fmt.Errorf("failed to marshal rejected_at: %w", err)
	}

	_, err = dynamoClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"request_id": &types.AttributeValueMemberS{Value: requestID},
		},
		UpdateExpression: aws.String("SET #status = :status, approved_by = :rejected_by, approved_at = :rejected_at"),
		ConditionExpression: aws.String("#status = :pending"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":      &types.AttributeValueMemberS{Value: StatusRejected},
			":rejected_by": &types.AttributeValueMemberS{Value: rejectedBy},
			":rejected_at": rejectedAtAV,
			":pending":     &types.AttributeValueMemberS{Value: StatusPending},
		},
	})

	if err != nil {
		var condCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &condCheckErr) {
			return fmt.Errorf("request is not in pending status")
		}
		return fmt.Errorf("failed to reject request: %w", err)
	}

	return nil
}
