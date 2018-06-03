#!/usr/bin/python
#Author: pyxloytous
#Offsec_ID: OS-xxxx
import os
import re
import sys
import random
import string
import argparse


description_1 = ''' 
!                                       [+]           Author:  pyxloytous            [+]
!                                       [+]          pyxloytous@gmail.com            [+] 
!                                       [+]               Version: 1.0               [+]

                                        [*]  An script to help in exploit development
                                 [*] Automates the works of Pattern creating and Offset finding
                         [*] Kali has Pattern_create.rb but it gives only first itiration of the offset
    [*] This script uses python regesx in such a way that it gives all itirations of the found pattern overwritten on an register
                                      [*] Automates the task of Badchar identification
                      [*] Creates Fresh pattern of all 256 possible ascii chars to identify badchars from them
             [*] Takes a copy pasted data file  from memory dump and compares them with the pattern been created
                     [*] After comparision it displayes the badchar tha terminated the sting copy to the memory
             [*] When the Bad chat identified, again bad char patter can be created removing the bad char identified \n'''


description = '''
|-------------------------------------------------------------------------------|
| [+]                        Author: pyxloytous              [+]                |
| [+]                       pyxloytous@gmail.com             [+]                |
| [+]                           Version: 1.1                 [+]                |
|-------------------------------------------------------------------------------|                                                             
| [*]  An script to help in exploit development                                 |
| [*] Automates the works of Pattern creating and Offset finding                |
| [*] Kali has Pattern_create.rb but it gives only first                        |
|     itiration of the offset                                                   |
| [*] This script uses python regesx in such a way that it gives                |
|     all itirations of the found pattern overwritten on an register            |
| [*] Automates the task of Badchar identification                              |
| [*] Creates Fresh pattern of all 256 possible ascii chars to identify         |
|   badchars from them                                                          |
| [*] Takes a copy pasted data file  from memory dump and compares them         |
|     with the pattern been created                                             |
| [*] After comparision it displays the badchar that terminated the string       |
|     copy process to the memory                                                        |
| [*] When the Bad chat identified, again bad char patter can be created        |
|     removing the bad char identified                                          |
|-------------------------------------------------------------------------------'\n\n'''

#version1.0 
#         - supported pattern creation for bad char identificatioin
#         - supported compare funcionality to compare the file with data copy pasted from the memory dump of debugger with existing bad char pattern file
#         - supprted functionality for removal of bad char removal and creating the pattern again

#version1.1
#        - supported functionality for creating patten to be used as bufer or crap while fuzzing the application
#        - supported functionality for identification of offset if a sub-patern overwrtitten on any cpu register is passed 






def scriptInfo(description):

    print b.YELLOW + "-" * 125 + b.ENDC

    print description

    print b.YELLOW + "-" * 125 + b.ENDC + '\n'


class b:
    #colors
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'


def argParser():
    #Parsses the args passed through command line
    parser = argparse.ArgumentParser() #instantiating parser
    subparser= parser.add_subparsers(dest='commands')  # instantiating subparsers with argument "cmd" with value commands to run functions based on a condition testing avaibility of test's value
    freshPattern = subparser.add_parser('fresh_badchar_pattern', help='Crate Fresh_Bad_Char_Pattern') #Adding subparsers to parser
    #freshPattern.add_argument('--fresh_pat_enable', action='store_true', default=False, help='Sets the boolen true to create fesh_Bad_Char_Pattern')
    badCharFreePat = subparser.add_parser('nobad_pattern', help='bad_char_free_pattern  -  Creates bad char free pattern if bad char passed')
    #badCharFreePat.add_argument('--no_bad_pat_enable', action='store_true', default=False, help='sets the boolean treo to create bad char free pattern')
    badCharFreePat.add_argument('-b', '--badchar', action='store', type=str, help='Takes badchars in comma joined form')
    comparePattern = subparser.add_parser('compare', help='Takes a existing bad_char_file and compares with the newly created bad_char_pattern in memory')
    #comparePattern.add_argument('--comp_enable', action='store_true', default=False, help='Sets the boolen Treu to start comparing')
    comparePattern.add_argument('-f', '--file', help='Takes eixisting bad_char_file to compare')
    patternCreate = subparser.add_parser('pattern_create', help='Takes a buffer size and creates pattern of that length')
    patternCreate.add_argument('-s', '--size', type=int, help='size of pattern to be created - ex: 10000')
    findOffset = subparser.add_parser('find_offset', help='Find offset of a sub-pattern in the pattern file used to create while sending exploit to target app')
    findOffset.add_argument('-p', '--pattern', type=str, help='Takes sub-pattern overwrittn on any register to find out its offset in the pattern file - ex: 10a7')
    findOffset.add_argument('-r', '--register', type=str, help='Takes name of a register - ex: EIP/ESP')
    findOffset.add_argument('-f', '--file', help='Takes path to pattern open and search the given sub-pattern in it and find its offset- ex: -f C:\some_dir\pattern_file or /some_dir/patternFile')                        
    args = parser.parse_args()
    #print "[+] Confirming what arguments to the command line parameters you have passed! \n\n"
    #print args,  '\n'
    return args


def BadCharFreshPatCreate(dirPath):
    #Creates Fresh pattern to test for bad char in memory - This has to be sent a s payload  to vuln app and got it written on mem
    byteArrayList = []
    byteArray = ""

    for i in range(0, 256):
        byteArrayList.append(format(i, '02x'))
        byteArray += format(i, '02x')

        byteArray = "\\x"
        byteArray += '\\x'.join(byteArrayList)
    print "New_Byte_Array = %s %s %s" % (b.YELLOW, byteArray[4:], b.ENDC)
    print
    newByteArrayFile = write2File(byteArray[4:], "Bad_Char_Pattern_File", dirPath)
    return newByteArrayFile
    return byteArray
 




def badCharFreePat(dirPath, badChar): #takes dirPath to save file in it, Badchar to remove it  - Creates a new Bad_Char_Free Array

    badCharRemovedArray = ""
    byteArrayList = []
    badCharList = []
    badChar = badChar
    badCharList = badChar.split(',')

    if badCharList:
        newBadCharList = []
        for i in badCharList:
            newBadCharList.append(int(i, 16))  #Converting hex into decimal
        #print "newBadCharList is \n", newBadCharList
        cleanRange = [x for x in range(0, 256) if x not in newBadCharList]  # Checking if items in badchar passed is not in the 256 possible possible characters
        #print "badrange is:\n", cleanRange
        for i in cleanRange:
            byteArrayList.append(format(i, '02x'))
            badCharRemovedArray += format(i, '02x')

        badCharRemovedArray = "\\x"
        badCharRemovedArray += '\\x'.join(byteArrayList)
    print "Bad_Char_Free_Byte_Array = %s \n\n %s %s" % (b.YELLOW, badCharRemovedArray[4:], b.ENDC)
    print
    newByteArrayFile = write2File(badCharRemovedArray[4:], "Bad_Char_Pattern_File", dirPath)
    return newByteArrayFile
    return badCharRemovedArray 



def comparePatternFiles(CharFileCopiedFromMemDump, dirPath):
    #If  new badchar file created from copy and pasete from debugger's memory area and  provided - compares with the existing bad_char_free_pattern_file to identify the badchars that stopped the pattern to be fully copied to stack
    existingPatDataList  = []
    CharFileCopiedFromMemDumpList = []
    matchedList = []
    unmatchedList = []
    badCharList = []
    CharFileCopiedFromMemDump = CharFileCopiedFromMemDump
    #Opening files to compare
    existingPatFile = dirPath + "/" + "Bad_Char_Pattern_File"
    if os.access(existingPatFile, os.R_OK):
        print '[+] Location of "existing pattern file" tarced ...\n\n"%s"\n'  % (existingPatFile)
        existingPatFleHandle = open(existingPatFile, 'r')
        for line in existingPatFleHandle.readlines():
            existingPatDataList = line.split("\\x")
            existingPatFleHandle.close()

    else:
        print '[-] "Bad_Char_Pattern_File" could not be found :( \n'

    CharFileCopiedFromMemDumpHandle = open(CharFileCopiedFromMemDump, 'rb')

    print "[+] Data from mem_file.txt here just to verify what we have actually to process further - if not properly copied, Please copy the data from memory dump properly and paste in the mem_file.txt\n"

    for line in CharFileCopiedFromMemDumpHandle.readlines():
        line = line.lower() #lowering the case just matchthe case with the pattern in bad_char_pattern_file
        if len(line) < 65: #checking if line copied from memory is 8 byte of length (normaly 16 byte lenth memory dump line has totoal length of approx 75 bytes)
            line = line[10:33].split() # slicing unwanted stuffs from left if line copied from 8 bytes long memory dump
            #print line
        else:
            line = line[10:57].split() # slicing unwanted stuffs from left if line copied from 16 byte long memory dump
            #print line
        for i in line:
            if i != "":
                CharFileCopiedFromMemDumpList.append(i)
    #print "Data stored in a list from mem_file.txt \n",CharFileCopiedFromMemDumpList
    print
    CharFileCopiedFromMemDumpHandle.close()




    # print CharFileCopiedFromMemDumpList
    if len(existingPatFile) != len(CharFileCopiedFromMemDump):
        print "[+] length of Existing pattern File and File with data copied from memdump is NOT equal in size \n"
   
        print "[-] Some mismatch found on the both supplied files!\n"
        print "[-] Existing Pattern File Data! \n"
        #x = "\\x"
        print ''.join(str(x) for x in existingPatDataList) + "\n\n" # joing the line with [""] for easy redability
        print "[-] Pattern copied from the application's stack dumped in memory and saved in mem_file.txt\n"
        print ''.join(str(x) for x in CharFileCopiedFromMemDumpList) + "\n\n"

        #print "existing_pat_list\n", existingPatDataList  #####
        #print "CharFileCopiedFromMemDumpList \n", CharFileCopiedFromMemDumpList  ######

    #Removing any enmpy space from pattern lists
        
    lst_1 = []    # Creating a new list to store empty space free data that would be furter copied to actual list "CharFileCopiedFromMemDumpList"
    for i in CharFileCopiedFromMemDumpList:
        if i != "" and i != "None":
            lst_1.append(i)
    CharFileCopiedFromMemDumpList = lst_1
    #print "[+] After removal empty spaces CharFileCopiedFromMemDumpList", CharFileCopiedFromMemDumpList
    
    
    lst_2 = []  #Creating a new list to store empty space free data that would be furter copied to actual list "existingPatDataList"
    for i in existingPatDataList:
        if i != "" and i != "None":
            lst_2.append(i)
    existingPatDataList = lst_2
    #print "[+] After removing empty spaces existingPatDataList", existingPatDataList

    print "[+] Comparing them now for you with eachother to detect badchars\n"

    for x, y in zip(CharFileCopiedFromMemDumpList, existingPatDataList):
        if x != "None":
            #print x
            if x == y:
                
                matchedList.append(x)
                #print "matched_list", matchedList
            else:
                badCharList.append(y)
                unmatchedList.append(x)
                index_pos = unmatchedList.index(x)
                break
    
    #print "[+] Pattern could be copied to the memory till the end of this line only :( \n"
    properCopiedStringLine = '\\x'.join(matchedList)
    print "[+] Below is the string line properly copied to memory - at the EOL bad_char found"
    print "[+] %s \n" % (properCopiedStringLine)
    print "[+] Following Badchars found"
    badChars = "\\".join(badCharList)
    print "[+] %s \n" % (badChars)

def write2File(object2Write, fileName, dirPath):

    if not os.path.isdir(dirPath): # or not os.path.isfile(dirPath):
        dirPath = newDir(dirPath)
        fileName = dirPath + fileName
    else:
        fileName = dirPath + fileName
    #writes to the file, the object it is supplied with
    f = open(fileName, 'w+')
    f.write(object2Write)
    f.close
    print b.GREEN + '[+] "Bad_Char_Pattern" written on \n "%s" %s! \n' % (fileName, b.ENDC) 
    print
    return f

def newDir(dirPath):
    #Checks for dir as path name given and creates if not available
    if os.path.isdir(dirPath):
        print b.RED + '[+] A Dir with name "%s" is already available exiting this peice of code %s \n' % (dirPath, b.ENDC)
        print
        return dirPath

    elif os.path.isfile(dirPath):
        print b.RED + '[+] A FILE with name "%s" is already available exiting this peice of code %s \n' % (dirPath, b.ENDC)

    else:
            #print b.GREEN + '[+] Creating desired folder ... \n' + b.ENDC
            #print
            head, tail = os.path.split(dirPath)
            if head and not os.path.isdir(head):  #if head and not actually present in filesystem, create it
               newDir(head)

            if tail:
                try:
                    os.mkdir(dirPath)
                    print b.GREEN + '[+] New Dir created as "%s" ! %s \n' % (dirPath, b.ENDC)
                    print
                except os.strerror as e:
                    print b.RED + '[+]An error occured while creating "%s" %s \n' % (dirPath, b.ENDC)
                    print b.RED + e.output.text + b.ENDC
                return dirPath


def patternCreate(patSize, dirPath):
    #Pattern Creating Function -Takes size of pattern 
    patternFile = "Pattern_File_%s" % (patSize)
    pattern = ""                #Empty place to save created pattern string
    for i in range (int(patSize)):
    #  pattern += random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
        pattern += random.choice(string.hexdigits)
        #pattern += string.hexdigits
    write2File(pattern, patternFile, dirPath) #Writing pattern to file
    print b.GREEN + "Pattern File Created with name Pattern_File_%s %s\n" % (patSize, b.ENDC)
    print pattern
    return patternFile





def offsetFinder(patternFile, reg, subPat):
    #Takes pattern data copied over any register and serached it through the pattern string to get its offset
    patternString = " " #saves pattern lines from the below file

    #File path to open pattern file created by above pattern script
    patternFile = patternFile  #Parsing pattern file created by patternCreate function
    if os.path.isfile(patternFile):
        print "pattern file found - finding offset to the subpattern provided!\n"
        f = open(patternFile, 'r')
        for line in f.readlines():
            patternString += line
    else:            
        print "Pattern File not found - offset to subpattern provided cannot be found\n"
            
   
    if (reg != "EIP") and (reg != "eip"):
        foundSubPat = [x.start() for x in re.finditer(subPat, patternString)]  #s_pattern = re.compile(p2find) #(Not neccessary to complie)
        print foundSubPat                
    else:  
        subPat = subPat.decode('hex')## EIP = "hex-encoded-value-43393936", hex-decoded value-"C996" # - Convert EIP sub_pattern from HEX to ASCII and reverse it as it is written in little Endian mode in EIP. - Rule applies only in EIP case as in EIP memory pointer od any sata/instruction is written in little Endian style
        subPat = subPat[::-1] # reversing subpattern before searching it in pattern file - reverse is required do to Little Endian style of writng in memory
        print "EIP_subpat:", subPat
        foundSubPat = [x.start() for x in re.finditer(subPat, patternString)]

    
    if foundSubPat:
        for item in foundSubPat:
            if item != "" or item != "None":
                print "[+] [%s] held sub-pattern: [%s] found! OFFSET is:  [%d]\n" % (reg, subPat,item -1) #off_set-1 = search_object starts from offset so need to subtract 1 from so that crap could not overwrite the starting byte of the seach object while overflowing)
                print
    else:
         print "[-] %s held sub-pattern did not match the pattern string!\n" % (reg)
         print





def main():

    curDir = os.getcwd()
        
    if os.getenv('OS') != "Windows_NT":
        scriptInfo(description)
        dirPath = curDir + '/Bad_Char_Dir/'
    else:
        print description
        dirPath = curDir + '\\Bad_Char_Dir\\'
        
    dirPath = newDir(dirPath) #Ceating directory in given path

    #patternFile = patternCreate(patSize, dirPath)
    #patternFile = dirPath + '/' + patternFile

    #parsing args
    args =  argParser()
    if "badchar" in args:
        badChar = args.badchar
    
    if 's' in args:
        patSize = args.s
    elif 'size' in args:
        patSize = args.size
        print "patSize", patSize
    if "p" in args:
        subPat = args.p
    elif "pattern" in args:
        subPat = args.pattern

    if "r" in args:
        reg = args.r
    elif "register" in args:
        reg = args.register

    if "find_offset" in args.commands:
        if "f" in args:
            patternFile = args.f
            if patternFile and not os.access(patternFile, os.F_OK):
                print "[-] Please provide pattern file path instead only file_name\n"
        elif "file" in args:
            patternFile = args.file
            if patternFile and not os.access(patternFile, os.F_OK):
                print "[-] Please provide pattern file path instead only file_name\n"

    if "compare" in args.commands:
        if "f" in args:
            mem_file = args.f
        elif "file" in args:
            mem_file = args.file

        if mem_file:
            if os.path.isfile(mem_file):
            #if tail == "mem_file.txt":
                CharFileCopiedFromMemDump = mem_file
            else:
                print '[+] If you have passed correct file path - please double check the file name is as "mem_file.txt"\n'
                sys.exit(0)



    #passing functions to main function
    try:
        if "fresh_badchar_pattern" in args.commands:
            BadCharFreshPatCreate(dirPath)
    except Exception as e:
        print '[-] Error occured in argument parcing - Please check the error below \n[-] {%s} \n'  % (e)

    try:
        if "nobad_pattern" in args.commands:
            badCharFreePat(dirPath, badChar)
    except Exception as e:
        print '[-] Error occured in argument parcing - Please check the error below \n[-] {%s} \n' % (e)

    #try:
    if "compare" in args.commands:
        comparePatternFiles(CharFileCopiedFromMemDump, dirPath)
    #except Exception as e:
    #    print '[-] Error occured in argument parcing - Please check the error below \n[-] {%s} \n' % (e)


    try:
        if "pattern_create" in args.commands:
            patternCreate(patSize, dirPath)
    except Exception as e:
        print '[-] Error occured in argument parcing - Please check the error below \n[-] {%s} \n' % (e)


    try:
        if "find_offset" in args.commands:
            offsetFinder(patternFile, reg, subPat)
    except Exception as e:
     print '[-] Error occured in argument parcing - Please check the error below \n[-] {%s} \n' % (e)





if __name__=='__main__':
    main()
