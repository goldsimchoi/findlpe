package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/normalone/lpeco/internal/model"
)

func appendFacts(ctx context.Context, path string, facts []model.Fact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open facts log: %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict facts log: %w", err)
	}
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for _, fact := range facts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := encoder.Encode(fact); err != nil {
			return fmt.Errorf("encode fact %q: %w", fact.ID, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush facts log: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync facts log: %w", err)
	}
	return nil
}

func loadFacts(ctx context.Context, path string) ([]model.Fact, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []model.Fact{}, nil
		}
		return nil, fmt.Errorf("open facts log: %w", err)
	}
	defer file.Close()

	var facts []model.Fact
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var fact model.Fact
		if err := json.Unmarshal(scanner.Bytes(), &fact); err != nil {
			return nil, fmt.Errorf("decode facts log line %d: %w", line, err)
		}
		facts = append(facts, fact)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read facts log after line %d: %w", line, err)
	}
	if facts == nil {
		facts = []model.Fact{}
	}
	return facts, nil
}
