FROM ubuntu:16.04
RUN apt-get update -qq \
    && apt-get install -yq python3-nose \
        python3-argh python3-requests
COPY ./ /work
WORKDIR /work
CMD ["nosetests3", "-v", "yrd"]
