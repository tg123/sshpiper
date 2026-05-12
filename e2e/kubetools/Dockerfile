FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl

RUN curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64 && \
    chmod +x ./kind && \
    mv ./kind /bin/kind

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
  chmod +x ./kubectl && \
  mv ./kubectl /bin/kubectl

# Install the Docker CLI using the modern keyring location (apt-key has been
# removed from recent Ubuntu releases).
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc

RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
   $(. /etc/os-release && echo \"$VERSION_CODENAME\") \
   stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && apt-get install -y docker-ce-cli