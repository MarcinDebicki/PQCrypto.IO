
# Acknowledgments

This package wouldn't have been possible without the work surrounding the project https://github.com/open-quantum-safe/liboqs. Truly amazing work, and a huge thanks for your dedication.

# My Motivation

This package was created as part of a cryptosystem I am working on. It was therefore developed to meet a current project need.  
My goal was not to create wrappers for all available algorithms but to focus on specific ones that I hope to use.  
If it proves useful to someone else, I’ll be happy.

# Native Libraries

The package includes native libraries for Windows and Linux systems.  
Thanks to the consistent API of liboqs, a balance was found between usage universality, genericity, and cross-platform compatibility.

I understand that, while reviewing the code, you may think it looks almost identical for each algorithm.  
In fact, until I encountered issues generating key pairs for ClassicMcEliece8192128 and ClassicMcEliece6688128, I was aiming for fully generic code.  
**The code is the way it is because that’s exactly how it’s supposed to be**, allowing me to quickly address any issues if they arise without introducing major changes. I believe no one who wants to use it would appreciate revolutionary changes.

The project includes natively compiled versions of liboqs for Windows and Linux. Detailed information on compiling liboqs can be found on the liboqs project pages.  
I am not including instructions for building native libraries (because even I don't really like these scripts), but I will have no problem if you replace them with your own.

# This is a C# Project

Cryptography involves constant operations on byte arrays, an approach far from object-oriented programming.  
To prevent silly mistakes, all byte arrays are encapsulated in strongly typed objects.  
For implementation flexibility, every library component is also an interface.

I encourage you not to use types in your programs that could be interpreted differently by various parts of the program.

# An Example of Use is Found in the Project PQCrypto.IO.POC

# If you have any questions or don't understand something

Please email me at: mentatd@gmail.com
