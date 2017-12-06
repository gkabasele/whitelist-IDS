GEN_SRC := Controller.cpp IDSController_constants.cpp IDSController_types.cpp
GEN_OBJ := $(patsubst %.cpp,%.o, $(GEN_SRC))

THRIFT_DIR := /usr/local/include/thrift
BOOST_DIR := /usr/local/include


INC := -I$(THRIFT_DIR) -I$(BOOST_DIR)

.PHONY: all clean

all: controller_client

%.o: %.cpp
	$(CXX) -g -Wall -std=gnu++0x -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H $(INC) -c $< -o $@


controller_client: Controller_Client.o $(GEN_OBJ)
	$(CXX) -g  $^ -o $@ -L/usr/local/lib -lthrift -lstdc++  -lnfnetlink -lnetfilter_queue -lpcap -lcrafter -lpthread -lresolv -lm -lbroker -ldl
clean:
	$(RM) *.o  controller_client
