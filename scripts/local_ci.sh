#!/usr/bin/env bash
set -euo pipefail

# Local CI Pipeline for JenkinsBreaker
# Validates code quality and functionality against local jenkins-lab before committing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
JENKINS_LAB_DIR="$PROJECT_ROOT/jenkins-lab"
JENKINS_URL="http://localhost:8080"
JENKINS_USER="admin"
JENKINS_PASS="admin"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Install Docker to run local CI."
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found."
        exit 1
    fi
    
    log_success "Requirements check passed"
}

start_jenkins_lab() {
    log_info "Starting jenkins-lab environment..."
    
    cd "$JENKINS_LAB_DIR"
    
    if docker-compose ps | grep -q "jenkins-lab.*Up"; then
        log_warning "jenkins-lab already running"
    else
        docker-compose up -d
        log_info "Waiting for Jenkins to be ready..."
        
        max_attempts=60
        attempt=0
        while [ $attempt -lt $max_attempts ]; do
            if curl -s -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL" &>/dev/null; then
                log_success "jenkins-lab is ready"
                break
            fi
            sleep 2
            attempt=$((attempt + 1))
        done
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "jenkins-lab failed to start within timeout"
            exit 1
        fi
    fi
    
    cd "$PROJECT_ROOT"
}

run_linting() {
    log_info "Running linting checks..."
    
    if ! ruff check src/ tests/ --config "$PROJECT_ROOT/pyproject.toml"; then
        log_error "Ruff linting failed"
        return 1
    fi
    
    if ! ruff format --check src/ tests/ --config "$PROJECT_ROOT/pyproject.toml"; then
        log_error "Ruff formatting check failed"
        return 1
    fi
    
    log_success "Linting passed"
    return 0
}

run_type_checking() {
    log_info "Running type checking..."
    
    if ! mypy src/jenkins_breaker/ --config-file "$PROJECT_ROOT/pyproject.toml"; then
        log_error "Mypy type checking failed"
        return 1
    fi
    
    log_success "Type checking passed"
    return 0
}

run_unit_tests() {
    log_info "Running unit tests..."
    
    if ! pytest tests/unit/ -v --tb=short; then
        log_error "Unit tests failed"
        return 1
    fi
    
    log_success "Unit tests passed"
    return 0
}

run_integration_tests() {
    log_info "Running integration tests against jenkins-lab..."
    
    export JENKINS_URL="$JENKINS_URL"
    export JENKINS_USER="$JENKINS_USER"
    export JENKINS_PASS="$JENKINS_PASS"
    
    if ! pytest tests/integration/ -v --tb=short -m integration; then
        log_error "Integration tests failed"
        return 1
    fi
    
    log_success "Integration tests passed"
    return 0
}

run_quick_exploit_test() {
    log_info "Running quick exploit validation..."
    
    if python3 tests/quick_exploit_test.py; then
        log_success "Quick exploit test passed"
        return 0
    else
        log_warning "Quick exploit test had issues (non-critical)"
        return 0
    fi
}

check_for_secrets() {
    log_info "Scanning for accidentally committed secrets..."
    
    if command -v gitleaks &> /dev/null; then
        if ! gitleaks detect --source "$PROJECT_ROOT" --no-git --verbose; then
            log_error "Potential secrets detected!"
            return 1
        fi
        log_success "No secrets detected"
    else
        log_warning "gitleaks not installed, skipping secret scanning"
    fi
    
    return 0
}

generate_report() {
    log_info "Generating CI report..."
    
    REPORT_FILE="$PROJECT_ROOT/ci_report.txt"
    
    cat > "$REPORT_FILE" << EOF
JenkinsBreaker Local CI Report
Generated: $(date)

Environment:
- Jenkins Lab: $JENKINS_URL
- Python: $(python3 --version)
- Docker: $(docker --version)

Test Results:
EOF
    
    if [ $LINTING_RESULT -eq 0 ]; then
        echo "- Linting: PASSED" >> "$REPORT_FILE"
    else
        echo "- Linting: FAILED" >> "$REPORT_FILE"
    fi
    
    if [ $TYPECHECK_RESULT -eq 0 ]; then
        echo "- Type Checking: PASSED" >> "$REPORT_FILE"
    else
        echo "- Type Checking: FAILED" >> "$REPORT_FILE"
    fi
    
    if [ $UNIT_RESULT -eq 0 ]; then
        echo "- Unit Tests: PASSED" >> "$REPORT_FILE"
    else
        echo "- Unit Tests: FAILED" >> "$REPORT_FILE"
    fi
    
    if [ $INTEGRATION_RESULT -eq 0 ]; then
        echo "- Integration Tests: PASSED" >> "$REPORT_FILE"
    else
        echo "- Integration Tests: FAILED" >> "$REPORT_FILE"
    fi
    
    if [ $SECRETS_RESULT -eq 0 ]; then
        echo "- Secret Scanning: PASSED" >> "$REPORT_FILE"
    else
        echo "- Secret Scanning: FAILED" >> "$REPORT_FILE"
    fi
    
    cat "$REPORT_FILE"
    log_info "Full report saved to: $REPORT_FILE"
}

cleanup() {
    log_info "Cleaning up..."
    
    if [ "${STOP_LAB:-true}" = "true" ]; then
        cd "$JENKINS_LAB_DIR"
        docker-compose down
        cd "$PROJECT_ROOT"
        log_info "jenkins-lab stopped"
    else
        log_info "Leaving jenkins-lab running (STOP_LAB=false)"
    fi
}

main() {
    log_info "Starting JenkinsBreaker Local CI Pipeline"
    echo "=========================================="
    
    check_requirements
    start_jenkins_lab
    
    cd "$PROJECT_ROOT"
    
    LINTING_RESULT=0
    TYPECHECK_RESULT=0
    UNIT_RESULT=0
    INTEGRATION_RESULT=0
    SECRETS_RESULT=0
    
    run_linting || LINTING_RESULT=$?
    run_type_checking || TYPECHECK_RESULT=$?
    run_unit_tests || UNIT_RESULT=$?
    run_integration_tests || INTEGRATION_RESULT=$?
    run_quick_exploit_test || true
    check_for_secrets || SECRETS_RESULT=$?
    
    echo ""
    log_info "CI Pipeline Summary:"
    echo "=========================================="
    
    generate_report
    
    TOTAL_FAILURES=$((LINTING_RESULT + TYPECHECK_RESULT + UNIT_RESULT + INTEGRATION_RESULT + SECRETS_RESULT))
    
    if [ "${CLEANUP:-true}" = "true" ]; then
        cleanup
    fi
    
    if [ $TOTAL_FAILURES -eq 0 ]; then
        log_success "All checks passed! Ready to commit."
        exit 0
    else
        log_error "CI pipeline failed with $TOTAL_FAILURES error(s)"
        exit 1
    fi
}

trap cleanup EXIT INT TERM

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
