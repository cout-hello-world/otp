CXXFLAGS = -std=c++11 -pedantic -Wall -Wextra -Werror -O2
LDLIBS = -lgmp
#CPPFLAGS = -DDEBUG
OBJECTS = otp.o

otp: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(OBJECTS) $(LDLIBS)
$(OBJECTS):

clean:
	$(RM) *.o otp
