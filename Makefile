.PHONY: dxt clean

# Create DXT package (no build needed since we use npx)
dxt:
	rm -rf dxt-package
	mkdir -p dxt-package
	cp manifest.json dxt-package/
	cp LICENSE dxt-package/
	cp README.md dxt-package/
	cd dxt-package && zip -r ../mcp-remote.dxt *
	@echo "DXT package created: mcp-remote.dxt"

# Clean build artifacts
clean:
	rm -rf dxt-package
	rm -f mcp-remote.dxt