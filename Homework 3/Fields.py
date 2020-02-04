#!/usr/bin/env python3
def determine_field(n):
    #For each element, determine if all elements of Zn -excluding 0- have a multiplicative inverse
    #We can do this by determining whether an element is relatively prime to n.
    z_index = 1
    while(z_index < n):
        #Perform gcd(z,k=n) and determine if == 1, if so there is a multiplicative inverse,
        #Otherwise there is not, which means it is a Comunitative ring.
        k = n
        z = z_index
        while(k):
            z,k = k, z % k
        if(z != 1):
            print("ring")
            return
        z_index += 1
    print("field")
    return

if __name__ == "__main__":
    num = int(input("Enter a number n:"))
    determine_field(num)
