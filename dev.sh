#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}🐛 Shai-Hulud 2.0 Killer${NC} - Development Helper"
echo ""

case "$1" in
    build)
        echo -e "${YELLOW}Building release...${NC}"
        docker compose run --rm build
        echo -e "${GREEN}✓ Build complete!${NC}"
        ;;
    dev)
        echo -e "${YELLOW}Starting development shell...${NC}"
        docker compose run --rm -it dev
        ;;
    run)
        echo -e "${YELLOW}Running scanner...${NC}"
        SCAN_PATH="${2:-$HOME/Projects}"
        docker compose run --rm -it -e TERM=xterm-256color \
            -v "$SCAN_PATH:/scan:ro" \
            run sh -c "cargo build --release 2>/dev/null && ./target/release/shai-hulud-killer /scan"
        ;;
    scan)
        # Quick scan with pre-built binary
        SCAN_PATH="${2:-$HOME/Projects}"
        docker compose run --rm -it -e TERM=xterm-256color \
            -v "$SCAN_PATH:/scan:ro" \
            run ./target/release/shai-hulud-killer /scan
        ;;
    json)
        # JSON output mode for CI/CD
        SCAN_PATH="${2:-$HOME/Projects}"
        docker compose run --rm \
            -v "$SCAN_PATH:/scan:ro" \
            run ./target/release/shai-hulud-killer --json /scan
        ;;
    test)
        echo -e "${YELLOW}Running tests...${NC}"
        docker compose run --rm test
        ;;
    clean)
        echo -e "${YELLOW}Cleaning up...${NC}"
        docker compose down -v
        echo -e "${GREEN}✓ Cleaned!${NC}"
        ;;
    extract)
        echo -e "${YELLOW}Extracting binary...${NC}"
        OUTPUT="${2:-./shai-hulud-killer}"
        docker compose run --rm -v "$(pwd):/out" build cp /app/target/release/shai-hulud-killer "/out/$OUTPUT"
        chmod +x "$OUTPUT"
        echo -e "${GREEN}✓ Binary extracted to $OUTPUT${NC}"
        ;;
    *)
        echo "Usage: $0 {build|dev|run|scan|json|test|clean|extract} [path]"
        echo ""
        echo "Commands:"
        echo "  build         - Build release binary"
        echo "  dev           - Start development shell"
        echo "  run [path]    - Build and run the scanner (default: ~/Projects)"
        echo "  scan [path]   - Run scanner with pre-built binary"
        echo "  json [path]   - Output JSON for CI/CD"
        echo "  test          - Run tests"
        echo "  clean         - Remove containers and volumes"
        echo "  extract [name]- Extract binary to host (default: ./shai-hulud-killer)"
        exit 1
        ;;
esac
