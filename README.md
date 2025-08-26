# XDP Killswitch



## Install

- Go >= 1.25

If on debian based, link properly asm and make sure you have all your dependencies installed:

```bash
sudo ln -sf /usr/include/asm-generic/ /usr/include/asm && \
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    libbpf-dev \
    llvm \
    clang \
    gcc-multilib \
    build-essential \
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-tools-generic
```

