/*
This header declares CLI command functions.
*/

#ifndef COMMAND_HANDLERS_H
#define COMMAND_HANDLERS_H

// commands declaration
void showHelp();
void executeFileCipher(int argc, char* argv[]);
void generateAES256Key();

#endif //COMMAND_HANDLERS_H