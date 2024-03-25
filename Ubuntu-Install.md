sudo apt update && sudo apt install -y python3-pip3 

pip3 install dnspython tld randstr

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo ln -s $HOME/go/bin/subfinder /usr/bin/subfinder

wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz
sudo tar -C /usr/bin/ -xzf assetfinder-linux-amd64-0.1.1.tgz 

go install github.com/projectdiscovery/alterx/cmd/alterx@latest
sudo ln -s $HOME/go/bin/alterx /usr/local/bin/alterx


go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
sudo ln -s $HOME/go/bin/shuffledns /usr/local/bin/shuffledns

wget https://github.com/trickest/resolvers/raw/main/resolvers-extended.txt -O resolvers.txt
