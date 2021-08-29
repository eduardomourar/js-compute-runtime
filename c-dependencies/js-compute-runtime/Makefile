# DEFINES := -DDEBUG -DJS_DEBUG

INIT_JS ?= test.js
WIZER ?= wizer

ROOT_SRC?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/..
SM_SRC=$(ROOT_SRC)/spidermonkey/
SM_OBJ=$(SM_SRC)lib/*.o
SM_OBJ+=$(SM_SRC)lib/*.a
FSM_SRC=$(ROOT_SRC)/js-compute-runtime/

WASI_CXX ?= /opt/wasi-sdk/bin/clang++

CXX_OPT ?= -O2

CXX_FLAGS := -std=gnu++17 -Wall -Werror -Qunused-arguments -fno-sized-deallocation -fno-aligned-new -mthread-model single -fPIC -fno-rtti -fno-exceptions -fno-math-errno -pipe -fno-omit-frame-pointer -funwind-tables
LD_FLAGS := -Wl,-z,noexecstack -Wl,-z,text -Wl,-z,relro -Wl,-z,nocopyreloc -Wl,-z,stack-size=1048576 -Wl,--stack-first

ifeq (,$(findstring g,$(CXX_OPT)))
ifneq (,$(shell which wasm-opt))
WASM_STRIP = wasm-opt --strip-debug -o $@ $@
endif
endif

FSM_CPP := $(wildcard $(FSM_SRC)*.cpp)
FSM_DEP := $(patsubst $(FSM_SRC)%.cpp,$(OBJDIR)%.d,$(FSM_CPP))
FSM_OBJ := $(patsubst $(FSM_SRC)%.cpp,$(OBJDIR)%.o,$(FSM_CPP))

.PHONY: all clean

all: js-compute-runtime.wasm

-include $(FSM_DEP)

%.o: $(FSM_SRC)%.cpp $(FSM_SRC)Makefile
	$(WASI_CXX) $(CXX_FLAGS) $(CXX_OPT) $(DEFINES) -I $(SM_SRC)include -MMD -MP -c -o $@ $<

js-compute-runtime.wasm: $(FSM_OBJ) $(SM_OBJ)
	$(WASI_CXX) $(CXX_FLAGS) $(CXX_OPT) $(DEFINES) $(LD_FLAGS) -o $@ $^
	$(WASM_STRIP)

initialized-js-compute-runtime.wasm: js-compute-runtime.wasm $(INIT_JS)
	cat $(INIT_JS) | $(WIZER) --allow-wasi --dir=. -r _start=wizer.resume -o $@ $<
