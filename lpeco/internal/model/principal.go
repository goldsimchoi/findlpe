package model

// Principal is the local security subject used for discretionary-access checks.
// SupplementaryGIDs must contain numeric group IDs, not display names.
type Principal struct {
	UID               int      `json:"uid"`
	GID               int      `json:"gid"`
	SupplementaryGIDs []int    `json:"supplementary_gids,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
}
