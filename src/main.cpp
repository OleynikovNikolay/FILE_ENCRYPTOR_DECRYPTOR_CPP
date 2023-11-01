#include "../include/commandHandlers.h"
#include "../include/utils.h"
#include "../include/fileCipher.h"
#include "../include/exceptions.h"
#include <string>
#include <iostream>


// SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes -decrypt "key" "inputfile" "outputfile" 
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << "-command" << std::endl;
        return EXIT_FAILURE;
    }

    toLower(argv[1]);
    std::string command = argv[1];

    if (command == "-help"){
        showHelp();
    } else if (command == "-aes" || command == "-xor"){
        try{
            executeFileCipher(argc, argv);
        } catch (SizeException& ex){
            std::cerr << ex.what() << std::endl;
        } catch (MethodException& ex){
            std::cerr << ex.what() << std::endl;
        } catch (ActionException& ex){
            std::cerr << ex.what() << std::endl;
        } catch (KeyException& ex){
            std::cerr << ex.what() << std::endl;
        }
    } else if (command == "-generate-aes256-key"){
        generateAES256Key();
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
};

