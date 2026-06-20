#!/bin/bash
# BugHunter AI — One-command installer
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}"
echo '██████╗ ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗ '
echo '██╔══██╗██║██╔══██╗██╔══██╗████╗  ██║██║  ██║██╔══██╗'
echo '██████╔╝██║██████╔╝███████║██╔██╗ ██║███████║███████║'
echo '██╔═══╝ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══██║██╔══██║'
echo '██║     ██║██║  ██║██║  ██║██║ ╚████║██║  ██║██║  ██║'
echo '╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝'
echo -e "${NC}"
echo -e "${BOLD}  🐟 PiRanha — The Autonomous Bug-Bounty Swarm${NC}"
echo -e "  53 specialized AI agents · Powered by Pi + Claude Code"
echo ""

# Check prerequisites
echo -e "${BOLD}Checking prerequisites...${NC}"

check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} $1"
        return 0
    else
        echo -e "  ${RED}[MISSING]${NC} $1 — $2"
        return 1
    fi
}

MISSING=0
check_tool "claude" "npm install -g @anthropic-ai/claude-code" || MISSING=1
check_tool "bun" "curl -fsSL https://bun.sh/install | bash" || MISSING=1

# Optional tools
echo ""
echo -e "${BOLD}Optional tools:${NC}"
check_tool "burpsuite" "https://portswigger.net/burp" || true
check_tool "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" || true
check_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" || true
check_tool "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" || true
check_tool "ffuf" "go install github.com/ffuf/ffuf/v2@latest" || true
check_tool "sqlmap" "pip install sqlmap" || true
check_tool "op" "brew install 1password-cli (for credential vault)" || true

if [ $MISSING -eq 1 ]; then
    echo ""
    echo -e "${RED}${BOLD}Required tools missing. Please install them first.${NC}"
    exit 1
fi

echo ""
echo -e "${BOLD}Installing BugHunter AI...${NC}"

# Copy skill
SKILL_DIR="$HOME/.claude/skills/BugBountyFramework"
if [ -d "$SKILL_DIR" ]; then
    echo -e "  ${YELLOW}[BACKUP]${NC} Existing installation found — backing up to ${SKILL_DIR}.bak"
    cp -r "$SKILL_DIR" "${SKILL_DIR}.bak.$(date +%Y%m%d%H%M%S)"
fi

mkdir -p "$HOME/.claude/skills"
cp -r skills/BugBountyFramework "$SKILL_DIR"
echo -e "  ${GREEN}[OK]${NC} Skill installed to $SKILL_DIR"

# Create memory directories
MEMORY_DIR="$HOME/.claude/MEMORY/BugBounty"
mkdir -p "$MEMORY_DIR"/{Findings,LearningLogs,PatternDB,TargetProfiles,Sessions,Vault}
echo -e "  ${GREEN}[OK]${NC} Memory directories created"

# Initialize databases (don't overwrite existing)
if [ ! -f "$MEMORY_DIR/PatternDB/master-patterns.md" ]; then
    echo "# Master Patterns" > "$MEMORY_DIR/PatternDB/master-patterns.md"
    echo "" >> "$MEMORY_DIR/PatternDB/master-patterns.md"
    echo "Patterns accumulate as you hunt. Each session adds what worked." >> "$MEMORY_DIR/PatternDB/master-patterns.md"
fi

if [ ! -f "$MEMORY_DIR/LearningLogs/effective-techniques.md" ]; then
    echo "# Effective Techniques" > "$MEMORY_DIR/LearningLogs/effective-techniques.md"
    echo "" >> "$MEMORY_DIR/LearningLogs/effective-techniques.md"
    echo "Techniques that confirmed vulnerabilities across engagements." >> "$MEMORY_DIR/LearningLogs/effective-techniques.md"
fi
echo -e "  ${GREEN}[OK]${NC} Pattern databases initialized"

# Make tools executable
chmod +x "$SKILL_DIR/Tools/"*.ts 2>/dev/null || true
echo -e "  ${GREEN}[OK]${NC} Tools marked executable"

echo ""
echo -e "${GREEN}${BOLD}BugHunter AI installed successfully!${NC}"
echo ""
echo -e "${BOLD}Quick Start:${NC}"
echo ""
echo -e "  ${CYAN}1.${NC} Open Claude Code:"
echo -e "     ${BOLD}claude${NC}"
echo ""
echo -e "  ${CYAN}2.${NC} Start hunting:"
echo -e "     ${BOLD}hunt https://your-target.com${NC}"
echo ""
echo -e "  ${CYAN}3.${NC} Check progress:"
echo -e "     ${BOLD}hunt https://your-target.com --status${NC}"
echo ""
echo -e "  ${CYAN}4.${NC} Store credentials securely:"
echo -e "     ${BOLD}Store creds for my-target: username admin@test.com, password P@ss${NC}"
echo ""
echo -e "${YELLOW}${BOLD}Remember:${NC} Only test targets you have authorization to test."
echo ""
