ALLOC_FILES = ['./dataset/alloc.func.1.c']
FREE_FILES = ['./dataset/free.func.1.c']
NEG_FILES = ['./dataset/neg.func.1.c']


if __name__ == '__main__':
    alloc_file = open(ALLOC_FILES[0], 'r')
    # free_file = open(FREE_FILES, 'r')
    # neg_file = open(NEG_FILES, 'r')
    functions = alloc_file.read().split('////')
    print(functions[0])
    
	