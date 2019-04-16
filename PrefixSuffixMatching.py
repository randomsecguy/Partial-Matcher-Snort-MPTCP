import numpy as np
import re, binascii

def make_pattern_array(patt_list, debug=0):
    '''
    Function to build a numpy matrix holding the set of pattern rules encoded with int16.
    Values in matrix which do not hold a pattern byte have the value -1.
    patt_list: a list of strings or bytestrings (i.e. b'\x24\x43')
    '''
    nr_patterns = len(patt_list)
    length_array = np.zeros(nr_patterns, dtype=np.int16)
    asciihexregex = '\|[A-F0-9]{2}(?: [A-F0-9]{2})*\|'

    #Initialize with a maximum pattern size of 50 characters
    pattern_array = np.zeros((nr_patterns, 50), dtype=np.int16)
    #Fill array/matrix with end-of-pattern markers, -1
    pattern_array[:,:] = -1   
        
    for patt_idx in range(nr_patterns):
                                
        if debug > 4:
            print(thispattformat,patt_list[patt_idx], type(patt_list[patt_idx]) is str)
            print(re.search(asciihexregex, patt_list[patt_idx]))
                        
        loop = True
        inpatt_pos = 0
        outpatt_pos = 0
        nr_patt_chars = len(patt_list[patt_idx])
        while loop:
            patt_remainder = patt_list[patt_idx][inpatt_pos:]

            #Check if there are remaining hex sections
            if re.search(asciihexregex, patt_remainder) != None:
                hexstart, hexend = re.search(asciihexregex, patt_remainder).span()
                hexstring = re.search(asciihexregex, patt_remainder).group()
                if debug > 2: 
                    print(patt_remainder[:hexstart], '   ',hexstring, hexstart,hexend)

                #Encode text before hex section
                for x in range(hexstart):
                    pattern_array[patt_idx,outpatt_pos] = ord(patt_remainder[x])
                    outpatt_pos += 1

                #Encode hex section
                for binval in binascii.unhexlify(hexstring[1:-1].replace(' ','')):
                    pattern_array[patt_idx,outpatt_pos] = binval
                    outpatt_pos += 1

                inpatt_pos += hexend

            else:
                #Encode text after hex section
                for x in range(len(patt_remainder)):
                    pattern_array[patt_idx,outpatt_pos] = ord(patt_remainder[x])
                    outpatt_pos += 1
                loop = False

            length_array[patt_idx] = outpatt_pos
            
    return pattern_array, length_array

def matchpacket(packet, p_arr, l_arr, missingindicator=ord('?'), debug = 0):
    '''
    Matches a single packet (represented as string, bytesequence,y or numpy array)
    against all patterns stored in the p_arr numpy patternarray.
    l_arr hold the number of bytes for each pattern
    '''
    #Convert incoming data to numpy array
    if type(packet)==str: 
        pkt_array = np.array([ord(c) for c in packet], dtype = np.int16)
    elif type(packet) == bytes:
        pkt_array = np.array([c for c in packet], dtype = np.int16)
    elif type(packet) == numpy.ndarray:
        pkt_array = packet
    else:
        raise SystemError('Unknown packet format')
        
    if debug > 4:
            print('Pktarray: %s'%pkt_array)

    #Check for matches in beginning or end of packet
    pktlen = len(packet)
    matchlist = list()
    for patt_idx in range(np.shape(p_arr)[0]):
        if debug > 3:
            print('Pattern: %20s \t Packet: %s'%(''.join([chr(c) for c in p_arr[patt_idx] if c>=0]), packet)) 
        start_offset = 0
        for start_offset in range(int(np.floor(l_arr[patt_idx]/2))+1):
            #Look for forward match i.e beginning of packet, matching to end of pattern
            if np.array_equal(p_arr[patt_idx, start_offset:l_arr[patt_idx]],  pkt_array[:l_arr[patt_idx]-start_offset]):
                matchlist.append([0, patt_idx, start_offset, 1-start_offset/l_arr[patt_idx]])

            #Look for backward match i.e end of packet, matching beginning of pattern
            if np.array_equal(p_arr[patt_idx, :l_arr[patt_idx]-start_offset],  pkt_array[-l_arr[patt_idx]+start_offset:]):
                matchlist.append([1, patt_idx, start_offset, 1-start_offset/l_arr[patt_idx]])
            if debug > 4:
                    print(start_offset, p_arr[patt_idx, :l_arr[patt_idx]-start_offset],  
                          pkt_array[-l_arr[patt_idx]+start_offset:])                    
                    
    #Check if there are matches when missing data is considered. 
    if missingindicator in pkt_array:
        misposarray = np.nonzero(pkt_array == missingindicator)[0]
        startmatch = max(0, misposarray.min()-l_arr.max())
        endmatch = misposarray.max()
        for startpos in range(startmatch, endmatch):
            test_array=pkt_array[startpos:]
            if len(test_array) > p_arr.shape[1]:
                cmp_arr = test_array[:p_arr.shape[1]]
            else:
                cmp_arr = np.zeros(p_arr.shape[1], dtype=np.int16)
                cmp_arr[:] = -2 
                cmp_arr[:len(test_array)] = test_array
            bmatch = l_arr >= np.sum(np.logical_or(cmp_arr==p_arr, cmp_arr == missingindicator ),axis=1)
            bmatch = np.logical_and(bmatch, np.sum(cmp_arr==p_arr, axis=1) >= np.ceil(l_arr/2))
            for patt_idx in np.nonzero(bmatch)[0]:
                pattlen = l_arr[patt_idx]
                cmp_arr = test_array[:pattlen]
                if debug > 5:
                    print(cmp_arr,p_arr[patt_idx,:pattlen], pattlen, example_patterns[patt_idx],packet)
                if pattlen == np.sum(np.logical_or(cmp_arr==p_arr[patt_idx,:pattlen], cmp_arr == missingindicator)):
                    matchlist.append([2, patt_idx, startpos, 1-np.sum(cmp_arr == missingindicator)/l_arr[patt_idx]])
    
    return matchlist



example_patterns=('SECRET', 'SECRETS', 'LONGPATTERN', 'SRTPT', 'MedPatt',  'hemligt', 'malicious_stuff', 'SRT', '4pat',
                  '|46 59|You are connected|48 45|', '|3A 10|dff|2F|You are connected|3A 10|oopi', 
                  '|48 45 58 4C 49 46 59|',
                  ".php?e=Adobe-2010-2884",
                  "/build2/serge/opafv.php",
                  "yoO4TAbn2tpl5DltCfASJIZ2spEJPLSn",
                  "/software/meta/Update/VersionCheckInfo.ini?c=",
                  "/ms162cfg.jsp?",
                  "|3C 6E 3E 56 3C 2A 3E|" ,
                  "|28 94 8D AB|",
                  "|8C 69 69 B2|",
                  "|31 70 C3 A7 A8 04 00 00|",
                  "|18 EE 90 7C 38 07 91 7C FF FF FF FF 32 07 91 7C AB 06 91 7C EB 06 91 7C 00 00 00 00 14 00 00 00 00 00 F6 76|" ,
                  "User-Agent|3A| Babylon|0D 0A|", 
                  "|2F|crx|2F|blobs",
                  "ThemeOverride|3D|",
                  "|3C 6E 3E|INIT|3C 2F 6E 3E|",
                  "name=|22|upload_file|22 3B|" 
                 )


testpackets =[
    'dfhjdsfghklsghsdghs sflghghn fghlkjsglkjhjlksgh sdköjhjklghh',
    '1gsglhjnerotj dsfgöjklserjbhsdfgh   malic',
    '2gsglhjnerotj dsfgöjklserjbhsdfgh   malicio',
    '3gsglhjnerotj dsfgöjklserjbhsdfgh   maliciou',
    '4gsdlkhgslkfghhlk   icious_stuff',
    'malic jhdfghn,df,ndfsgn,sdfg ',
    'malicio jhdfghn,df,ndfsgn,sdfg ',
    'maliciou jhdfghn,df,ndfsgn,sdfg ',
    'ious_stuff sdfishlfgskh sdfklh  sdlfhs dflh sdf sldhf ',
    'SEC dfghldfg',
    'RET dfghg',
    'sldhgsfg SECR',
    'sdlgjksdf RET',
    'TPT sdgfg heml',
    'LIFY test hex',
    'sfadf hextes HEXL',
    'connectedHEjkhgaa',
    'sdafhjhksdfFYYou are co',
    b'\x88\x12\x8C\x69',
    'This is a string which also contains the target SE??ET but with missing characters in it',
    'Should work also in the end:S??RE?S',
    'h?m?i?t and in the beginning ',
    'end missing works ??m?igt',
    '??CRET this line starts with missing bytes, design requires missing inside, so no match',
    'a LONGP?????N and another target at end will create two matches heml',
]

p_arr, l_arr = make_pattern_array(example_patterns)

debug = 3
for packet in testpackets[:]:
    resultlist = matchpacket(packet, p_arr[:], l_arr[:], debug = debug)
    if resultlist != list():
        for matchinfo in resultlist:            
            matchtype, patt_idx, start_offset, coverage = matchinfo
            matchtypestring = ['FORWARDMATCH ', 'BACKWARDMATCH', 'MISSING-MATCH'][matchtype]
            if debug > 2:
                print('%s offset: %-3d Pattern size: %-3d Coverage: %-3.2f Patt: %-20s Pkt: %-27.27s'%
                          (matchtypestring, start_offset, l_arr[patt_idx], coverage,
                         ''.join([chr(c) for c in p_arr[patt_idx] if c>=0]), packet))

