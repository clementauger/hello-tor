build:
	go build -tags prod -o hello-tor
clean:
	rm hello-tor
run:
	go run .
prod:
	go run -tags prod .
