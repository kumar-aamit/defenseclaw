package enforce

import (
	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type PolicyEngine struct {
	store *audit.Store
}

func NewPolicyEngine(store *audit.Store) *PolicyEngine {
	return &PolicyEngine{store: store}
}

func (e *PolicyEngine) IsBlocked(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "install", "block")
}

func (e *PolicyEngine) IsAllowed(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "install", "allow")
}

func (e *PolicyEngine) IsQuarantined(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "file", "quarantine")
}

func (e *PolicyEngine) Block(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "install", "block", reason)
}

func (e *PolicyEngine) Allow(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "install", "allow", reason)
}

func (e *PolicyEngine) Unblock(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "install")
}

func (e *PolicyEngine) Quarantine(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "file", "quarantine", reason)
}

func (e *PolicyEngine) ClearQuarantine(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "file")
}

func (e *PolicyEngine) Disable(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "runtime", "disable", reason)
}

func (e *PolicyEngine) Enable(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "runtime")
}

func (e *PolicyEngine) SetSourcePath(targetType, name, path string) {
	if e.store == nil {
		return
	}
	_ = e.store.SetSourcePath(targetType, name, path)
}

func (e *PolicyEngine) SetAction(targetType, name, sourcePath string, state audit.ActionState, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetAction(targetType, name, sourcePath, state, reason)
}

func (e *PolicyEngine) GetAction(targetType, name string) (*audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.GetAction(targetType, name)
}

func (e *PolicyEngine) ListBlocked() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListByAction("install", "block")
}

func (e *PolicyEngine) ListAllowed() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListByAction("install", "allow")
}

func (e *PolicyEngine) ListAll() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListAllActions()
}

func (e *PolicyEngine) ListByType(targetType string) ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListActionsByType(targetType)
}

func (e *PolicyEngine) RemoveAction(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.RemoveAction(targetType, name)
}
