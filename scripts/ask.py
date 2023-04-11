import openai
import os

ALLOC_FILES = ['./dataset/alloc.func.1.c']
FREE_FILES = ['./dataset/free.func.1.c']
NEG_FILES = ['./dataset/neg.func.1.c']

CHAT_MODEL = 'gpt-3.5-turbo'
# messages = [
# 	{
# 		'role': 'system',
# 		'content': 'You are an assistant who helps me to decide whether a function written in C code is for deallocating memory or not.'
# 	},
# 	{
# 		'role': 'user',
# 		'content': "I need you simply answer yes or no. No any other words!"
# 	},
# 	{
# 		'role': 'user',
# 		'content': ''
# 	},
# ]

# messages = [
# 	{
# 		'role': 'system',
# 		'content': 'You are an assistant who helps me to decide whether a function written in C code is for allocating memory or not.'
# 	},
# 	{
# 		'role': 'user',
# 		'content': "I need you simply answer yes or no. No any other words!"
# 	},
# 	{
# 		'role': 'user',
# 		'content': ''
# 	},
# ]

messages = [
	{
		'role': 'system',
		'content': 'You are an assistant who helps me to decide whether a function written in C code is for allocating/deallocating memory or not.'
	},
	{
		'role': 'user',
		'content': "I need you simply answer yes or no. No any other words!"
	},
	{
		'role': 'user',
		'content': ''
	},
]

if __name__ == '__main__':
	openai.api_key = os.getenv('OPENAI_API_KEY')

	# alloc_file = open(ALLOC_FILES[0], 'r')
	# free_file = open(FREE_FILES[0], 'r')
	neg_file = open(NEG_FILES[0], 'r')
	functions = neg_file.read().split('////')
	for i in range(0, len(functions)):
		messages[2]['content'] = functions[i]
	# print(messages)

		completion = openai.ChatCompletion.create(
			model = CHAT_MODEL,
			messages = messages
		)

		print(completion['choices'][0]['message']['content'])