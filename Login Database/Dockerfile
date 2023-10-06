FROM golang:1.16.6

RUN mkdir /app
ADD . /app

WORKDIR /app

RUN go get -d -v ./...
RUN go install -v ./...

RUN go build -o main .
RUN echo 'First Docker'
EXPOSE 8000
CMD ["/app/main"]
