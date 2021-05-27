This project aims to encrpyt and decrypt a file using AES. This command is ran through the 
command line and you will also specify your code in the command line. The only two commands you'll
need are 'nano ~/.bashrc' and 'source ~/.bashrc'. 

1. When you type in the 'nano ~/.bashrc' command, you will enter 
the bashrac file. Scroll down to the comment that says " Some more ls aliases". Press enter to 
create a new line and type "alias" + name of command you want for command line + " ='python3 " + 
the file location of Decrypt.py. 

2. Type ctrl+x and then Y and then ENTER. 

3. Enter the 'source ~/.bashrc' command, it will refresh the environment so you can now execute
from the command line.

4. I created the shortcut to be 'crypt' and the file I want to encrypt is called 'new.txt' so in 
the command line I will type 'crypt new.txt'. The file will then execute and will give me the 
encrpyted and decrypted file results. It will also create an encrpyted file called 'encrypt.txt'.

5. Note that two files will appear in the same location as your text document you are encrpyting. 
One file is encrypt.txt, which was explained above, and the second is key.key, which holds the key
for decrypting the file.