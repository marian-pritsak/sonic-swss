CXX=g++
CC=$(CXX)
CXXFLAGS=-g -O0 -std=c++11 -Wall -pedantic
CPPFLAGS        = -I. -I${CURDIR}/../inc
LDFLAGS         = -L. \
                  -L${CURDIR}/../lib
BIN=bmt_debug

FLX_SDK_DIR     = ..
FLX_SDK_SRC_DIR = ${FLX_SDK_DIR}/src/
INC_DIR         = ${FLX_SDK_DIR}/inc/
LIBS_DIRS       = -L${FLX_SDK_DIR}/lib/
LIBS            = ${LIBS_DIRS} -L${CURDIR}/../lib 
TEST_LIBS       = -L${FLX_SDK_DIR}/lib/ -L${CURDIR}/../lib 
INC_DIRS        = -I${INC_DIR}
OBJ_DIR         = obj

SRC=$(wildcard *.cpp)
OBJ=$(SRC:%.cpp=%.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) -o $(BIN) $^ ${INC_DIRS} ${LIBS} 

%.o: %.c
	$(CXX) ${INC_DIRS}  $@ -c $<

test: $(OBJ) 
	$(CXX) -o $(BIN).test $^ ${INC_DIRS} ${TEST_LIBS}

clean:
	rm -f $(OBJ) core *.a *.so
	rm -f $(BIN)
