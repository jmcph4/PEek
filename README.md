# PEek - a PE file viewer#
---
PEek is a command-line PE file viewer written in C. So far it's very limited in its feature base; however, this will change progressively.

## Features ##
### Current ###
- View the PE file header
- View (most) of the PE file optional header (except the `DllCharacteristics` field for now)

### Planned ###
- View *all* of the PE file optional header
- View all of the sections
- Have different modes
  - "Raw" mode (like now)
  - "Friendly" mode (explanation of codes, etc.)
  - Various modes for automating several common analyses

## Technical ##
PEek is written in C and successfully compiles with GCC 4.9.2 via MinGW-64. Building is simple:
    
    git clone https://github.com/hetra/PEek.git
    cd PEek
    gcc src\main.c -o PEek