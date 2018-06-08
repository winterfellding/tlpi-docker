### What's this repo for

This is a repository for setting up an enviroment for learning the linux programming interface book on non-linux place, like mac or windows PC.

### How to use

1. clone the repo
2. build your docker image with `docker build -t <tag-name> .`
3. run the image in interactive mode `docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined <image-name>`, the extra param is for gdb debugging security setting.
4. happy learning, the code and built binary are all in `/tlpi-dist`, debug with gdb to see what happened in the programs.