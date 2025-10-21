TARGET 		= yellow
SRC 		= main.go

GROUP_ID 	= $$(id -g)
USER_ID 	= $$(id -u)

.PHONY: all
all: compile

.PHONY: help
help:
	@echo "\033[34myellow targets:\033[0m"
	@perl -nle'print $& if m{^[a-zA-Z_-\d]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: compile
compile: ## compile the project
	@go build -o $(TARGET) $(SRC)

.PHONY: docker
docker: ## builds a docker image from source
	@docker build -t yellow \
		--build-arg USER_ID=$(USER_ID) \
		--build-arg GROUP_ID=$(GROUP_ID) \
		.
.PHONY: clean
clean: ## cleans up the project
	rm -f $(TARGET)

.PHONY: tidy
tidy: ## runs tidy and formatting
	@go mod tidy
	@gofmt -s -w .

.PHONY: release-build
release-build: ## makes a release build locally on the current commit
	@goreleaser release --skip=publish --snapshot
