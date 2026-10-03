package audit

import "time"

type Report struct {
	Version       int                  `json:"version"`
	Host          string               `json:"host"`
	StartedAt     time.Time            `json:"started_at"`
	FinishedAt    time.Time            `json:"finished_at"`
	Success       bool                 `json:"collection_success"`
	MD5           MD5Result            `json:"md5"`
	Login         LoginResult          `json:"login"`
	Existence     ExistenceResult      `json:"existence"`
	Errors        []Issue              `json:"errors"`
	Files         FilesResult          `json:"files_monitoring"`
	Processes     ProcessResult        `json:"process_monitoring"`
	Alerts        []Alert              `json:"alerts"`
	Notifications []NotificationResult `json:"notifications"`
}

type Issue struct {
	Module  string `json:"module"`
	Message string `json:"message"`
}

type Change struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before string `json:"before_md5,omitempty"`
	After  string `json:"after_md5,omitempty"`
}

type MD5Result struct {
	Enabled         bool              `json:"enabled"`
	Success         bool              `json:"success"`
	BaselineCreated bool              `json:"baseline_created"`
	Scanned         int               `json:"scanned"`
	Skipped         int               `json:"skipped_non_regular"`
	MissingRoots    []string          `json:"missing_roots"`
	Changes         []Change          `json:"changes"`
	Cumulative      map[string]uint64 `json:"changes_total"`
	LastChange      *time.Time        `json:"last_change_at,omitempty"`
}

type LoginRecord struct {
	ID        string    `json:"id,omitempty"`
	Method    string    `json:"method,omitempty"`
	SourceIP  string    `json:"source_ip"`
	LoginTime time.Time `json:"login_time"`
	User      string    `json:"user"`
	Terminal  string    `json:"terminal"`
}

type LoginResult struct {
	Enabled bool          `json:"enabled"`
	Success bool          `json:"success"`
	Source  string        `json:"source"`
	Path    string        `json:"path"`
	Record  *LoginRecord  `json:"record"`
	Records []LoginRecord `json:"records"`
	Pending bool          `json:"pending"`
}

type CheckResult struct {
	Path         string `json:"path"`
	ExpectedType string `json:"expected_type"`
	ActualType   string `json:"actual_type"`
	Exists       bool   `json:"exists"`
	Matches      bool   `json:"matches"`
	Error        string `json:"error,omitempty"`
}

type ExistenceResult struct {
	Enabled      bool          `json:"enabled"`
	Success      bool          `json:"success"`
	Missing      int           `json:"missing"`
	TypeMismatch int           `json:"type_mismatch"`
	Items        []CheckResult `json:"items"`
}

type OutputPaths struct {
	JSON   string
	Prom   string
	Latest string
	Log    string
}

type Alert struct {
	Module  string `json:"module"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Message string `json:"message"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

type NotificationResult struct {
	Server string `json:"server"`
	IP     string `json:"ip,omitempty"`
	Sent   int    `json:"datagrams_sent"`
	Error  string `json:"error,omitempty"`
}
