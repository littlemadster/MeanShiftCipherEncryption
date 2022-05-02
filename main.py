'''
Maddie Sirok
CAP4410
Segmentation and Block Chain Encryption
'''

import cv2
import sklearn.cluster as sk
import numpy

'''
uses mean shift to find RGB keyspace of image
'''
def meanShift(img):
    # filter to reduce noise
    img = cv2.medianBlur(img, 3)

    # flatten the image
    flat_image = img.reshape((-1, 3))
    flat_image = numpy.float32(flat_image)

    # meanshift
    bandwidth = sk.estimate_bandwidth(flat_image, quantile=0.08, n_samples=5000)
    ms = sk.MeanShift(bandwidth=bandwidth, max_iter=800, bin_seeding=True)
    sk.MeanShift()
    ms.fit(flat_image)
    labeled = ms.labels_

    # get number of segments
    segments = numpy.unique(labeled)
    print('Number of key blocks: ', segments.shape[0])

    # get the average color of each segment
    total = numpy.zeros((segments.shape[0], 3), dtype=float)
    count = numpy.zeros(total.shape, dtype=float)
    for i, label in enumerate(labeled):
        total[label] = total[label] + flat_image[i]
        count[label] += 1
    avg = total / count
    avg = numpy.uint8(avg)

    # returns the keyspace in RBG values from avg computed above
    keySpace_RGB = avg
    return keySpace_RGB

'''
converts RGB values to HEX values
'''
def rgb2hex(keyspaceList_rgb):
    keyspaceList_hex = []

    # loops through number of image color segments
    for i in range(len(keyspaceList_rgb)):
        rgb = []
        rgb.append(keyspaceList_rgb[i][0])
        rgb.append(keyspaceList_rgb[i][1])
        rgb.append(keyspaceList_rgb[i][2])
        r, g, b = rgb
        hexValue = '%02x%02x%02x' % (r, g, b)
        keyspaceList_hex.append(hexValue)

    return keyspaceList_hex

'''
encryptes blocks using ACSII values and modulus
'''
def blockEnc(pBlk, kBlk):
    cBlk = ''

    # loops through each letter in the block and encrypts it
    for i in range(6):
        cASCII = ord(pBlk[i]) + ord(kBlk[i]) % 128
        cBlk += chr(cASCII)
    #print(pBlk, " + ", kBlk, " = ", cBlk)
    return cBlk

'''
encryptes the plaintext blocks with the keyspace blocks
'''
def encrypt(plainBlocks, keyBlocks):
    ciphertext = ''
    keySpaceCounter = 0

    # loops through all the plaintext blocks to encrypt it
    for i in range(int(len(plainBlocks))):
        if keySpaceCounter == len(keyBlocks): # allows keyblocks to be looped through and repeated
            keySpaceCounter = 0
        cipherT = blockEnc(plainBlocks[i], keyBlocks[keySpaceCounter])
        ciphertext += cipherT
        keySpaceCounter += 1

    return ciphertext

'''
decrypts blocks using ACSII values and modulus
'''
def blockDec(cBlk, kBlk):
    pBlk = ''

    # loops through each letter in the block and decrypts it
    for i in range(6):
        if (ord(cBlk[i]) - ord(kBlk[i]) % 128) < 0 or (ord(cBlk[i]) - ord(kBlk[i]) % 128) == 10:
            cASCII = 32
        else:
            cASCII = ord(cBlk[i]) - ord(kBlk[i]) % 128
        pBlk += str(chr(cASCII))
    #print(cBlk, " + ", kBlk, " = ", pBlk)
    return pBlk

'''
decrypts the ciphertext blocks with the keyspace blocks
'''
def decrypt(cipherBlocks, keyBlocks):
    plaintext = ''
    keySpaceCounter = 0

    for i in range(int(len(cipherBlocks))):
        if keySpaceCounter == len(keyBlocks):
            keySpaceCounter = 0
        plainT = blockDec(cipherBlocks[i], keyBlocks[keySpaceCounter])
        plaintext += plainT
        keySpaceCounter += 1

    return plaintext

'''
splits a string into blocks of 6 letters
'''
def six_block(text):
    # checks size of plaintext and adds padding as needed
    blocks = 0
    if (len(text)/6).is_integer():
        blocks = len(text)/6
    else:
        while not (len(text)/6).is_integer():
            text = text + '0'
            blocks = len(text)/6

    #print(plaintext) #plaintext with padding
    #print(blocks) #number of blocks

    # chunkates the plaintext into blocks
    blockList = []
    x = 0
    r = 6
    for i in range(int(blocks)):
        chonk = text[x:r]
        blockList.append(chonk)
        x += 6
        r += 6

    return blockList

'''
main function of code
'''
def main():
    # images used for keyspaces
    keyImage1 = cv2.imread('dog.bmp')
    keyImage2 = cv2.imread('dog_changed.png')
    keyImage3 = cv2.imread('blocks_L-150x150.png')
    keyImage4 = cv2.imread('rug.png')

    # aquiring keyspace
    keys_rgb = meanShift(keyImage1)
    keyspace_HEX = rgb2hex(keys_rgb)
    print('Segment Values HEX: ', keyspace_HEX)

    keysI2 = meanShift(keyImage2)
    i2_hex = rgb2hex(keysI2)
    print('Segment I4: ', i2_hex)

    keysI3 = meanShift(keyImage3)
    i3_hex = rgb2hex(keysI3)
    print('Segment I4: ', i3_hex)

    keysI4 = meanShift(keyImage4)
    i4_hex = rgb2hex(keysI4)
    print('Segment I4: ', i4_hex)

    # reads text file and prints to show before encryption
    textfile = open('Plaintext.txt', 'r')
    plaintext = textfile.read()
    textfile.close()
    print(plaintext)

    # encrypts text using true key image
    plainBlock = six_block(plaintext)
    ciphertext = encrypt(plainBlock, keyspace_HEX)
    print("Ciphertext: \'", ciphertext, "\'")

    # decrypts text using all images
    cipherBlock = six_block(ciphertext) # blocks ciphertext into blocks
    decryptedTextI1 = decrypt(cipherBlock, keyspace_HEX)
    print("Decrypted Text: ", decryptedTextI1)
    print("\n")
    decryptedTextI2 = decrypt(cipherBlock, i2_hex)
    print("Decrypted Text: ", decryptedTextI2)
    print("\n")
    decryptedTextI3 = decrypt(cipherBlock, i3_hex)
    print("Decrypted Text: ", decryptedTextI3)
    print('\n')
    decryptedTextI4 = decrypt(cipherBlock, i4_hex)
    print("Decrypted Text: ", decryptedTextI4)


''' Executes Main Function '''
main()

'''
Logical steps to create code & Pseudocode
1. chunkate plaintext to blocks of 6 (DONE)_
2. use blockcipher() function to encrypt each block
3. append encrypted block to ciphertext

for every letter in block:
    convert plaintext letter to ASCII
    convert key value to ASCII
    cipherletter = (asciiP + asciiK) mod (total ascii table length)
    add cipherletter to ciphertext

print plaintext
print ciphertext
'''