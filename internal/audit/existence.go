package audit

import "os"

func collectExistence(c ExistenceConfig) (ExistenceResult, []Issue) {
	r := ExistenceResult{Enabled: c.Enabled, Success: true, Items: []CheckResult{}}
	if !c.Enabled {
		return r, nil
	}
	entries, err := loadChecks(c)
	if err != nil {
		r.Success = false
		return r, []Issue{{"existence", err.Error()}}
	}
	var issues []Issue
	for _, entry := range entries {
		item := CheckResult{Path: entry.Path, ExpectedType: entry.Type, ActualType: "missing"}
		info, err := os.Stat(entry.Path)
		switch {
		case os.IsNotExist(err):
			r.Missing++
		case err != nil:
			item.ActualType = "unknown"
			item.Error = err.Error()
			r.Success = false
			issues = append(issues, Issue{"existence", entry.Path + ": " + err.Error()})
		default:
			item.Exists = true
			item.ActualType = "other"
			if info.IsDir() {
				item.ActualType = "directory"
			} else if info.Mode().IsRegular() {
				item.ActualType = "file"
			}
			item.Matches = entry.Type == "any" || entry.Type == item.ActualType
			if !item.Matches {
				r.TypeMismatch++
			}
		}
		r.Items = append(r.Items, item)
	}
	return r, issues
}
