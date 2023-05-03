FROM golang:1.20.2-alpine3.17

RUN apk --update --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing --repository http://dl-cdn.alpinelinux.org/alpine/edge/main add \ 
    #vscode
    libstdc++

WORKDIR /app

COPY --chown=1001:1001 . .

RUN mkdir /app/ssl 

# default gid 65533 and primary. mirror_proxy app also set 644 permissions. 
# need to check https://osqa-ask.wireshark.org/questions/61543/use-tshark-with-sslkeylogfile-to-get-decrypted-tls-data/
RUN adduser -S -u 1001 goapp \
     && addgroup -S -g 1001 goapp && addgroup goapp goapp \
     && addgroup -S -g 1002 mirror_proxy \
     && addgroup goapp mirror_proxy \
     && chown -R goapp:goapp /app \
     && chown -R goapp:mirror_proxy /app/ssl \
     && chmod g+rwX /app -R 

USER 101

# RUN mv ./.mitmproxy ~/.mitmproxy

RUN GOOS=linux GOARCH=amd64 go build -v -o ./mirror_proxy .

RUN chmod +x ./mirror.sh

EXPOSE 10080

CMD ["./mirror.sh"]