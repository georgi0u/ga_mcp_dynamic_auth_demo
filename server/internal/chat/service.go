package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpservice"
	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
)

type Service struct {
	store  *store.Store
	mcp    *mcpservice.Service
	apiKey string
	model  string
}

func New(
	store *store.Store,
	mcp *mcpservice.Service,
	apiKey string,
	model string,
) *Service {
	return &Service{
		store:  store,
		mcp:    mcp,
		apiKey: strings.TrimSpace(apiKey),
		model:  strings.TrimSpace(model),
	}
}

func (s *Service) Bootstrap(
	ctx context.Context,
	userID string,
) (*store.Conversation, []store.Message, error) {
	conversation, err := s.store.GetOrCreatePrimaryConversation(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	messages, err := s.store.ListMessages(ctx, conversation.ID, 200)
	if err != nil {
		return nil, nil, err
	}
	return conversation, messages, nil
}

func (s *Service) BeginTurn(
	ctx context.Context,
	userID string,
	input string,
) (*store.Conversation, *store.Message, error) {
	conversation, err := s.store.GetOrCreatePrimaryConversation(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	message, err := s.store.AppendMessage(ctx, conversation.ID, "user", strings.TrimSpace(input))
	if err != nil {
		return nil, nil, err
	}
	return conversation, message, nil
}

func (s *Service) CompleteTurn(
	ctx context.Context,
	userID string,
	conversation *store.Conversation,
	input string,
) (*store.Message, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is not configured")
	}

	toolDefinitions, toolIndex, err := s.mcp.BuildToolCatalog(ctx, userID)
	if err != nil {
		return nil, err
	}

	client := openai.NewClient(option.WithAPIKey(s.apiKey))
	params := responses.ResponseNewParams{
		Model: openai.ChatModel(s.model),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String(strings.TrimSpace(input)),
		},
		Tools: buildOpenAITools(toolDefinitions),
	}
	if conversation.LastOpenAIResponseID != "" {
		params.PreviousResponseID = openai.String(conversation.LastOpenAIResponseID)
	}

	response, err := client.Responses.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("openai response request failed: %w", err)
	}

	for turns := 0; turns < 8; turns++ {
		toolOutputs, hasCalls, err := s.collectToolOutputs(ctx, toolIndex, response.Output)
		if err != nil {
			return nil, err
		}
		if !hasCalls {
			break
		}

		response, err = client.Responses.New(ctx, responses.ResponseNewParams{
			Model: openai.ChatModel(s.model),
			Input: responses.ResponseNewParamsInputUnion{
				OfInputItemList: toolOutputs,
			},
			PreviousResponseID: openai.String(response.ID),
			Tools:              buildOpenAITools(toolDefinitions),
		})
		if err != nil {
			return nil, fmt.Errorf("openai follow-up request failed: %w", err)
		}
	}

	assistantText := strings.TrimSpace(response.OutputText())
	if assistantText == "" {
		assistantText = "The model returned an empty response."
	}

	if err := s.store.UpdateConversationResponse(ctx, conversation.ID, response.ID); err != nil {
		return nil, err
	}
	conversation.LastOpenAIResponseID = response.ID
	return s.store.AppendMessage(ctx, conversation.ID, "assistant", assistantText)
}

func buildOpenAITools(definitions []mcpservice.ToolDefinition) []responses.ToolUnionParam {
	tools := make([]responses.ToolUnionParam, 0, len(definitions))
	for _, definition := range definitions {
		tools = append(tools, responses.ToolUnionParam{
			OfFunction: &responses.FunctionToolParam{
				Name:        definition.FunctionName,
				Description: openai.String(definition.Description),
				Parameters:  definition.Parameters,
				Strict:      openai.Bool(false),
				Type:        "function",
			},
		})
	}
	return tools
}

func (s *Service) collectToolOutputs(
	ctx context.Context,
	toolIndex map[string]mcpservice.ToolDefinition,
	output []responses.ResponseOutputItemUnion,
) ([]responses.ResponseInputItemUnionParam, bool, error) {
	results := make([]responses.ResponseInputItemUnionParam, 0)
	hasCalls := false

	for _, item := range output {
		call := item.AsFunctionCall()
		if call.Name == "" {
			continue
		}
		hasCalls = true

		definition, ok := toolIndex[call.Name]
		if !ok {
			results = append(results, responses.ResponseInputItemParamOfFunctionCallOutput(
				call.CallID,
				fmt.Sprintf(`{"error":"unknown tool %q"}`, call.Name),
			))
			continue
		}

		args := map[string]any{}
		if strings.TrimSpace(call.Arguments) != "" {
			if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
				results = append(results, responses.ResponseInputItemParamOfFunctionCallOutput(
					call.CallID,
					fmt.Sprintf(`{"error":"invalid tool arguments: %s"}`, strings.ReplaceAll(err.Error(), `"`, `'`)),
				))
				continue
			}
		}

		toolOutput, err := s.mcp.CallTool(ctx, definition, args)
		if err != nil {
			return nil, false, err
		}
		results = append(results, responses.ResponseInputItemParamOfFunctionCallOutput(call.CallID, toolOutput))
	}

	return results, hasCalls, nil
}
