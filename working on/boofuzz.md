```console
def hexStrEndianSwap(theString):
        """Rearranges character-couples in a little endian hex string to
        convert it into a big endian hex string and vice-versa. i.e. 'A3F2'
        is converted to 'F2A3'
 
        @param theString: The string to swap character-couples in
        @return: A hex string with swapped character-couples. -1 on error."""

        # We can't swap character couples in a string that has an odd number
        # of characters.
        if len(theString)%2 != 0:
            return -1

        # Swap the couples
        swapList = []
        for i in range(0, len(theString), 2):
            swapList.insert(0, theString[i:i+2])

        # Combine everything into one string. Don't use a delimeter.
        return ''.join(swapList)
new = hexStrEndianSwap("948576")
# original hex 948576

s = "768594"


i = int(s, 16)
print("the original manual swap " + s)
print("hex string swap program " + new)
print("decimal string after LE swap " + str(i))




from boofuzz import *


def main():


    port = 9999
    host = '127.0.0.1'
    protocol = 'udp'

    session = Session(
            target=Target(
                connection = SocketConnection(host, port, proto=protocol),
            ),
    )

    s = "982567"

    i = int(s, 16)



    s_initialize("nonstring")
    s_dword(7767444, fuzzable=False)



    #s_byte(255, fuzzable=False)                        # FF
    #s_word(65535, fuzzable=False)                      # FF:FF
    #s_dword(4294967295 , fuzzable=False)               # FF:FF:FF:FF
    #s_qword(18446744073709551615, fuzzable=False)      # FF:FF:FF:FF:FF:FF:FF:FF
    s_string("test")

    #s_string("KSTET", fuzzable=False)
    #s_delim(" ", fuzzable=False)
    #s_string("FUZZ")
    #s_static("\r\n")

    session.connect(s_get("nonstring"))
    session.fuzz()

if __name__ == "__main__":
    main()
```
