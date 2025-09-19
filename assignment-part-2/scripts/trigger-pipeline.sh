#!/bin/bash

# Demo script to trigger the CI/CD pipeline
# This script shows how to trigger different pipeline scenarios

set -e  # Exit on error

echo "🚀 DevOps Assignment - CI/CD Pipeline Demo"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if git is available
if ! command -v git &> /dev/null; then
    print_error "Git is not installed!"
    exit 1
fi

# Get current git status
CURRENT_BRANCH=$(git branch --show-current)
print_status "Current branch: $CURRENT_BRANCH"

echo ""
echo "Choose a demo scenario:"
echo "1) 🔄 Trigger CI/CD on Pull Request (runs tests, builds, but doesn't deploy)"
echo "2) 🚀 Trigger Full Production Deployment (main branch)"
echo "3) 🧪 Run Local Tests Only"
echo "4) 📊 Show Pipeline Status"
echo "5) 🔍 View Recent Pipeline Runs"
echo ""

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo ""
        print_status "Creating a demo pull request to trigger CI/CD..."
        
        # Create a feature branch
        FEATURE_BRANCH="demo/pipeline-test-$(date +%s)"
        git checkout -b $FEATURE_BRANCH
        
        # Make a small change to trigger the pipeline
        echo "# Pipeline Test - $(date)" >> README.md
        git add README.md
        git commit -m "🧪 Demo: Test CI/CD pipeline
        
        This commit demonstrates:
        - Automated testing and linting
        - Docker image building
        - Security scanning with Gemini
        - Infrastructure validation
        
        Triggered by: Demo script"
        
        print_warning "To complete the PR demo:"
        echo "1. Push this branch: git push origin $FEATURE_BRANCH"
        echo "2. Create a PR from GitHub UI"
        echo "3. Watch the pipeline run at: https://github.com/ssidharths/idurar-erp-crm/actions"
        
        print_success "Feature branch '$FEATURE_BRANCH' created with demo commit"
        ;;
        
    2)
        echo ""
        print_warning "This will trigger a PRODUCTION deployment!"
        read -p "Are you sure? (yes/no): " confirm
        
        if [[ $confirm == "yes" ]]; then
            if [[ $CURRENT_BRANCH != "main" ]]; then
                print_status "Switching to main branch..."
                git checkout main
                git pull origin main
            fi
            
            # Make a deployment-worthy change
            echo "# Production Deployment - $(date)" >> DEPLOYMENT_LOG.md
            git add DEPLOYMENT_LOG.md
            git commit -m "🚀 Production Deployment
            
            Changes in this deployment:
            - Updated application version
            - Applied infrastructure changes
            - Deployed to EKS cluster
            
            Deployment ID: DEPLOY-$(date +%Y%m%d-%H%M%S)"
            
            print_status "Pushing to main branch to trigger production deployment..."
            git push origin main
            
            print_success "Production deployment triggered!"
            echo ""
            echo "Monitor the deployment:"
            echo "📊 GitHub Actions: https://github.com/ssidharths/idurar-erp-crm/actions"
            echo "☁️  AWS Console: https://console.aws.amazon.com/eks/"
            echo "📈 CloudWatch: https://console.aws.amazon.com/cloudwatch/"
        else
            print_warning "Production deployment cancelled"
        fi
        ;;
        
    3)
        echo ""
        print_status "Running local tests..."
        
        if [ -d "app" ]; then
            cd app
            
            # Check if dependencies are installed
            if [ ! -d "node_modules" ]; then
                print_status "Installing dependencies..."
                npm install
            fi
            
            # Run linting
            print_status "Running ESLint..."
            npm run lint
            
            # Run tests
            print_status "Running unit tests..."
            npm test
            
            print_success "All local tests passed! ✅"
        else
            print_error "App directory not found! Make sure you're in the project root."
        fi
        ;;
        
    4)
        echo ""
        print_status "Checking pipeline status..."
        
        # This requires GitHub CLI (gh) to be installed and authenticated
        if command -v gh &> /dev/null; then
            gh run list --limit 5
        else
            print_warning "GitHub CLI not installed. Visit: https://github.com/YOUR_USERNAME/devops-assignment/actions"
        fi
        ;;
        
    5)
        echo ""
        print_status "Recent pipeline runs..."
        
        if command -v gh &> /dev/null; then
            gh run list --limit 10 --json status,conclusion,createdAt,headBranch,workflowName \
                --template '{{range .}}{{.createdAt | timeago}} - {{.workflowName}} ({{.headBranch}}) - {{.conclusion}}{{"\n"}}{{end}}'
        else
            print_warning "GitHub CLI not installed. Install from: https://cli.github.com/"
            echo "Or visit: https://github.com/YOUR_USERNAME/devops-assignment/actions"
        fi
        ;;
        
    *)
        print_error "Invalid choice!"
        exit 1
        ;;
esac

echo ""
echo "🔗 Useful Links:"
echo "📖 GitHub Repository: https://github.com/ssidharths/idurar-erp-crm"
echo "🔄 Actions: https://github.com/YOUR_USERNAME/devops-assignment/actions"
echo "☁️ AWS Console: https://console.aws.amazon.com/"
echo "📊 ECR: https://console.aws.amazon.com/ecr/"
echo "🚢 EKS: https://console.aws.amazon.com/eks/"
echo "📈 CloudWatch: https://console.aws.amazon.com/cloudwatch/"

echo ""
print_success "Demo script completed!"
