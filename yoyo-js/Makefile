.PHONY: bootstrap-check bootstrap-strict bootstrap-lock bootstrap-update-baseline bootstrap-selfhost bootstrap-native test-stage2 evolution-check-ps1 bootstrap-native-ps1 bootstrap-native-windows diagnose-stage3-ps1

# Detect platform: prefer PowerShell on Windows, fall back to bash
ifeq ($(OS),Windows_NT)
  SHELL := powershell
  RUNNER := powershell -ExecutionPolicy Bypass -File scripts/bootstrap-check.ps1
  STAGE2 := powershell -ExecutionPolicy Bypass -File scripts/test-stage2.ps1
  EVOLUTION_PS1 := powershell -ExecutionPolicy Bypass -File scripts/evolution-check.ps1
  BOOTSTRAP_NATIVE_PS1 := powershell -ExecutionPolicy Bypass -File scripts/bootstrap-native.ps1
  BOOTSTRAP_NATIVE_WINDOWS := powershell -ExecutionPolicy Bypass -File scripts/bootstrap-native-windows.ps1
  DIAGNOSE_STAGE3_PS1 := powershell -ExecutionPolicy Bypass -File scripts/diagnose-stage3.ps1
else
  RUNNER := bash scripts/bootstrap-check.sh
  STAGE2 := bash scripts/test-stage2.sh
endif

bootstrap-check:
	$(RUNNER)

bootstrap-strict:
	$(RUNNER) --strict

bootstrap-lock:
	$(RUNNER) --strict --lock

bootstrap-update-baseline:
	$(RUNNER) --strict --update-baseline

bootstrap-selfhost:
	bash scripts/bootstrap-selfhost.sh

bootstrap-native:
	bash scripts/bootstrap-native.sh

evolution-check-ps1:
	$(EVOLUTION_PS1)

bootstrap-native-ps1:
	$(BOOTSTRAP_NATIVE_PS1) -Stages 3

bootstrap-native-windows:
	$(BOOTSTRAP_NATIVE_WINDOWS) -Stages 3

diagnose-stage3-ps1:
	$(DIAGNOSE_STAGE3_PS1)

test-stage2:
	$(STAGE2)
