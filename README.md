<font size=6>**intcpt**</font>

<font size=5> intercept a run process and read/write memory </font>

------

### 1. Requirements

In order to build this project, The commands `autoconf` and `automake` need to be installed in your system, for example

#### 1.1 Debian/Ubuntu

```sh
sudo apt install autoconf automake
```

#### 1.2 Centos/Fedora

```sh
sudo yum install autoconf automake
```

#### 1.2 ArchLinux/Manjaro

```sh
sudo pacman -S autoconf automake
```

### 2. Build

Go the root of project:

```sh
./autogen.sh
./configure
make
```

And your project should compile. Now you are all set with a lean template to build upon.

Your binary should be available at `src/intcpt`.

*NOTE:*
`autogen.sh` and `configure` only run for the first time or `makefile.am`, `configure.ac` modified.

### 3. Usage

**NOTE: This program(intcpt) must be run with root privileges!**

```sh
sudo /path/to/intcpt [PID] [VARIABLE_NAME]
```

- PID: the running process pid(you can use `pgrep/pidof` to get pid from program name)
- VARIABLE_NAME: the global/static variable you want to search

### 4. Bugs, Requests and Support

For bug reports, feature requests and general questions, please open issues.
