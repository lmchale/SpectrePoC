FLAGS_DEBUG = -Og -g -march=native -Wall -pedantic -fvar-tracking-assignments
CFLAGS += -std=c99 $(FLAGS_DEBUG)
CXXFLAGS += -std=c++14 $(FLAGS_DEBUG)
#CXXFLAGS += -std=c++14 $(FLAGS_DEBUG) -Wold-style-cast

PROGRAM = spectre spectre-victim spectre-attacker
OBJ = udp_socket.o hex_util.o

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
	$(CXX) $(CXXFLAGS) -pthread $^ -lrt -o $@

spectre-attacker: spectre-attacker.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -pthread $^ -lrt -o $@

%: %.c
	$(CC) $(CFLAGS) $^ -o $@

%: %.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

.PHONY: clean     
clean:
	rm -f $(PROGRAM) $(OBJ)

