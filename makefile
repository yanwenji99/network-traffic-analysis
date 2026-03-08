CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -MMD -MP
INCLUDES := -I./include

SRC := \
	./src/main.cpp \
	./src/graph.cpp \
	./src/read_to_flow.cpp \
	./src/sorting.cpp \
	./src/find_graph.cpp \
	./src/find_path.cpp \
	./src/check_scan.cpp \
	./src/check_star.cpp \
	./src/check_range.cpp

BUILD_DIR ?= ./build
BIN_DIR := $(BUILD_DIR)/bin
OBJ_DIR := $(BUILD_DIR)/obj

TARGET ?= $(BIN_DIR)/main.exe
DATA ?= ./data/network_data.csv
JSON_OUT ?= ./data/output/results.json
PYTHON ?= python
UI_SCRIPT ?= ./python/ui_gui.py
PCAP_IN ?= ./data/catch_data.pcap
PCAP_OUT ?= ./data/network_data.csv
OBJ := $(patsubst ./src/%.cpp,$(OBJ_DIR)/%.o,$(SRC))
DEP := $(OBJ:.o=.d)

.PHONY: all run batch deps ui pcap2csv batch_pcap clean rebuild

all: $(TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CXX) $(OBJ) -o $(TARGET)

$(OBJ_DIR)/%.o: ./src/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BIN_DIR):
	if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"

$(OBJ_DIR):
	if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)"

run: $(TARGET)
	$(TARGET) $(DATA)

batch: $(TARGET)
	if not exist ".\\data\\output" mkdir ".\\data\\output"
	$(TARGET) $(DATA) --json-out $(JSON_OUT)

deps:
	$(PYTHON) -m pip install -r requirements.txt

ui:
	$(PYTHON) $(UI_SCRIPT)

pcap2csv:
	$(PYTHON) .\\scripts\\pcap_to_csv.py --input $(PCAP_IN) --output $(PCAP_OUT)

batch_pcap: $(TARGET) pcap2csv
	if not exist ".\\data\\output" mkdir ".\\data\\output"
	$(TARGET) $(PCAP_OUT) --json-out $(JSON_OUT)

clean:
	-rmdir /S /Q "$(BUILD_DIR)" >nul 2>&1
	-del /Q main.exe >nul 2>&1
	-del /Q .\src\*.o >nul 2>&1
	-del /Q .\src\*.d >nul 2>&1

rebuild: clean all

-include $(DEP)
