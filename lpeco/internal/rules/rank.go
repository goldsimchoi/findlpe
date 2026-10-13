package rules

import "github.com/normalone/lpeco/internal/model"

type RankInput struct {
	PrivilegeBoundary bool
	ControlConfirmed  bool
	TriggerConfirmed  bool
	SemanticsResolved bool
	Confidences       []model.Confidence
	MissingFacts      []string
}

type RankResult struct {
	Priority         model.Priority
	Confidence       model.Confidence
	ValidationStatus model.ValidationStatus
}

// Rank keeps operational priority independent from evidence confidence. A P0
// requires a complete, high-confidence consumer/control/trigger chain.
func Rank(input RankInput) RankResult {
	confidence := aggregateConfidence(input.Confidences, input.MissingFacts)
	result := RankResult{Priority: model.PriorityP2, Confidence: confidence, ValidationStatus: model.ValidationIncomplete}
	if input.ControlConfirmed && input.SemanticsResolved && confidence == model.ConfidenceHigh && len(input.MissingFacts) == 0 {
		result.ValidationStatus = model.ValidationReadOnly
	}
	if !input.PrivilegeBoundary || !input.ControlConfirmed {
		return result
	}
	result.Priority = model.PriorityP1
	if input.TriggerConfirmed && input.SemanticsResolved && confidence == model.ConfidenceHigh && len(input.MissingFacts) == 0 {
		result.Priority = model.PriorityP0
	}
	return result
}

func aggregateConfidence(values []model.Confidence, missing []string) model.Confidence {
	if len(missing) >= 2 {
		return model.ConfidenceLow
	}
	confidence := model.ConfidenceHigh
	for _, value := range values {
		switch value {
		case model.ConfidenceLow:
			return model.ConfidenceLow
		case model.ConfidenceMedium:
			confidence = model.ConfidenceMedium
		case model.ConfidenceHigh:
		default:
			return model.ConfidenceLow
		}
	}
	if len(missing) == 1 && confidence == model.ConfidenceHigh {
		confidence = model.ConfidenceMedium
	}
	return confidence
}
