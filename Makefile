.PHONY: build dxt clean

# Build TypeScript source
build:
	npm run build

# Create DXT package
dxt: build
	mkdir -p dxt-package
	cp manifest.json dxt-package/
	cp -r dist dxt-package/
	cp package.json dxt-package/
	cp LICENSE dxt-package/
	cp README.md dxt-package/
	cd dxt-package && zip -r ../mcp-remote.dxt *
	@echo "DXT package created: mcp-remote.dxt"

# Clean build artifacts
clean:
	rm -rf dist
	rm -rf dxt-package
	rm -f mcp-remote.dxt