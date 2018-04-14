CFLAGS += -std=c99 -Og -g -march=native
CXXFLAGS += -std=c++11 -Og -g -march=native

PROGRAM = spectre spectre-victim spectre-attacker
OBJ = udp-socket.o

GIT_SHELL_EXIT := $(shell git status --porcelain 2> /dev/null >&2 ; echo $$?)

# It can be non-zero when not in git repository or git is not installed.
# It can happen when downloaded using github's "Download ZIP" option.
ifeq ($(GIT_SHELL_EXIT),0)
# Check if working dir is clean.
GIT_STATUS := $(shell git status --porcelain)
ifndef GIT_STATUS
GIT_COMMIT_HASH := $(shell git rev-parse HEAD)
CFLAGS += -DGIT_COMMIT_HASH='"$(GIT_COMMIT_HASH)"'
endif
endif
     
.PHONY: all   
all: $(PROGRAM)

spectre-victim: spectre-victim.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@

%: %.c
	$(CC) $(CFLAGS) $^ -o $@

%: %.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

.PHONY: clean     
clean:
	rm -f $(PROGRAM) $(OBJ)

