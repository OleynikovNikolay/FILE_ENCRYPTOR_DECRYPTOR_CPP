#include "../include/exceptions.h"
#include "../include/utils.h"

#include <iomanip>


// validatio of file cipher
void validateCipher(int argc, char* argv[]){
    bool validitySize = isValid_size(argc);
    bool validityMethod = isValid_method(argv);
    bool validityAction = isValid_action(argv);
    bool validityKey = isValid_key(argv);

    if (!validitySize){
        throw SizeException();
    }

    if (!validityMethod){
        throw MethodException();
    }

    if (!validityAction){
        throw ActionException();
    }

    if(!validityKey){
        throw KeyException();
    }
}