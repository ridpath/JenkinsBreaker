#!/usr/bin/env bash
set -euo pipefail

# Development Environment Setup for JenkinsBreaker
# Installs pre-commit hooks and validates local CI pipeline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

check_python() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found. Install Python 3.9+ first."
        exit 1
    fi
    
    python_version=$(python3 --version | awk '{print $2}')
    log_success "Python $python_version detected"
}

check_docker() {
    log_info "Checking Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not found. jenkins-lab will not work."
        log_warning "Install Docker: https://docs.docker.com/get-docker/"
    else
        docker_version=$(docker --version | awk '{print $3}' | tr -d ',')
        log_success "Docker $docker_version detected"
    fi
}

install_package() {
    log_info "Installing JenkinsBreaker package..."
    
    cd "$PROJECT_ROOT"
    
    if [ ! -d ".venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv .venv
    fi
    
    source .venv/bin/activate
    
    log_info "Installing development dependencies..."
    pip install -e ".[dev]" --quiet
    
    log_success "Package installed"
}

install_precommit() {
    log_info "Installing pre-commit hooks..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    if ! command -v pre-commit &> /dev/null; then
        log_info "Installing pre-commit..."
        pip install pre-commit --quiet
    fi
    
    pre-commit install
    
    log_success "Pre-commit hooks installed"
}

verify_precommit() {
    log_info "Verifying pre-commit configuration..."
    
    cd "$PROJECT_ROOT"
    source .venv/bin/activate
    
    if pre-commit run --all-files --show-diff-on-failure; then
        log_success "Pre-commit hooks verified"
    else
        log_warning "Some pre-commit hooks failed. Review output above."
    fi
}

install_gitleaks() {
    log_info "Checking for gitleaks..."
    
    if command -v gitleaks &> /dev/null; then
        gitleaks_version=$(gitleaks version)
        log_success "gitleaks already installed: $gitleaks_version"
        return
    fi
    
    log_warning "gitleaks not found. Secret scanning will be limited."
    log_info "Install from: https://github.com/gitleaks/gitleaks"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "macOS detected. Install with: brew install gitleaks"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "Linux detected. Install with package manager or download binary."
    fi
}

test_jenkins_lab() {
    log_info "Testing jenkins-lab..."
    
    cd "$PROJECT_ROOT/jenkins-lab"
    
    if ! docker-compose ps | grep -q jenkins-lab; then
        log_info "Starting jenkins-lab..."
        docker-compose up -d
        
        log_info "Waiting for Jenkins to be ready..."
        max_attempts=60
        attempt=0
        while [ $attempt -lt $max_attempts ]; do
            if curl -s -u admin:admin http://localhost:8080 &>/dev/null; then
                log_success "jenkins-lab is accessible at http://localhost:8080"
                log_info "Credentials: admin/admin"
                break
            fi
            sleep 2
            attempt=$((attempt + 1))
        done
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "jenkins-lab failed to start"
            return 1
        fi
    else
        log_success "jenkins-lab already running"
    fi
    
    cd "$PROJECT_ROOT"
}

main() {
    echo "========================================"
    log_info "JenkinsBreaker Development Setup"
    echo "========================================"
    echo ""
    
    check_python
    check_docker
    install_package
    install_precommit
    install_gitleaks
    
    echo ""
    log_info "Running initial pre-commit validation..."
    verify_precommit
    
    echo ""
    log_info "Testing jenkins-lab environment..."
    test_jenkins_lab
    
    echo ""
    echo "========================================"
    log_success "Development environment ready!"
    echo "========================================"
    echo ""
    log_info "Next steps:"
    echo "  1. Activate virtual environment: source .venv/bin/activate"
    echo "  2. Run local CI: ./scripts/local_ci.sh"
    echo "  3. Start development: Review DEVELOPMENT.md"
    echo ""
    log_info "jenkins-lab: http://localhost:8080 (admin/admin)"
}

main "$@"
