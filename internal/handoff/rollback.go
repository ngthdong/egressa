package handoff

type RollbackResult struct {
	Session string
	HadArm  bool
}

func Rollback(armer *StandbyArmer, session string) RollbackResult {
	_, _, _, _, hadArm := armer.Snapshot(session)
	armer.Reset(session)
	return RollbackResult{Session: session, HadArm: hadArm}
}
