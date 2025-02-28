



import numpy as np

from os import walk,system
from os.path import getsize


from sys import argv


from subprocess import Popen,PIPE

from re import sub


from copy import deepcopy


#0,1,2,3,4,5,6,7,8
#A,B,[C,D,[E,F],G,H,I]



class search_for_file_ext:

	
	def __init__(self):
	

		self.tags = np.array(['iptables','ip6tables'])
		self.tags_bytes = [ np.array(list(bytes(data.encode('utf-8')))) for data in self.tags]
		
		self.max_tags = np.array([ len(data) for data in self.tags_bytes]).max()
		self.tags_bytes = np.array([ np.append(data,np.ones(self.max_tags - len(data)  )*-2) if len(data) != self.max_tags else data   for data in self.tags_bytes ])
		
		self.lost = np.array([])
		

		self.storage_used = self.storage_used()
		# Found_file_path, line
		self.found_files = np.array([])
		
		self.neg = -1
			
		self.file_size_mapped = 0
		
		
		self.cached_mentions = np.array(['',''])

		self.ignore_in_storage_search = np.array(['/proc/kcore'])
		
		

	def storage_used(self):
		

		x = np.array([ sub("[\s]+"," ",str(data)).split(" ")[2] for data in np.array(Popen("df -a".split(" "),stdout=PIPE,stderr=PIPE).communicate()[0].decode('utf-8').split('\n')[1:-1])])
		# x = np.array([sub('[\s]+',' ',data).split(' ')[2] for data in np.array(Popen("df -a".split(" "),stdout=PIPE,stderr=PIPE).communicate()[0].decode('utf-8').split('\n')[1:-1]) ])
		
		x = x[x != "-"]

		return x.astype(np.int32).sum() * 1024
	
	def firewall_tags(self):
		domains = pd.read_csv('domain.csv')
		ips_found = np.load('ip_.npy')
		
		self.tags = np.concatnate([self.tags,domains,ips_found])
		
		
		
	def file_search(self,filename):
		
		
		with open(filename,'r',encoding='utf-8') as write_data: x = write_data.readlines()
	
	
	
	def pad_to_byte_shape(self,x):
		return np.append(x,(np.ones(self.max_tags - (x.shape[0] % self.max_tags) )*self.max_tags)).reshape(-1,1,self.max_tags)

	
	def byte_decode_match_zero_non_error(self,data):
#		x = bytes(np.append(np.zeros(shape=[data]),x)).decode('utf-8')
		try:
			return bytes(np.append(np.zeros(shape=[data]),x)).decode('utf-16').encode('utf-8').decode('utf-8')
		except:
			return 0 
	

	def op_insert_removeal(self,filename,indexs_overwrite):

		index_buffer = 0

		# import pdb; pdb.set_trace()
		try:
			with open('x_test_marcus','wb') as write_data:
				

				# import pdb; pdb.set_trace()
				write_data.write(bytearray(indexs_overwrite.tolist()))
				# if (indexs_overwrite[indexs_overwrite == index_buffer].size > 0):

				# 	import pdb; pdb.set_trace()

				# 	write_data.write(chunk)


				index_buffer += 1
		except:
			pass

		#with open("")


	def op_read(self,filename):
		
		found_values_return = np.zeros(shape=[1,2])
		# import pdb; pdb.set_trace()
		print(filename)
		if (filename[:4] == '/dev' or filename[:4] == '/run' or filename[:8] == "/var/run"):
			return found_values_return
		
		self.search_current()

		
		


		indexs_overwrite = np.array([])

		op_cond_found = False

		print(filename)

		x_copy_for_chunk_insertion = np.array([])
		try:

			if (self.ignore_in_storage_search[self.ignore_in_storage_search == filename].size == 0):
				self.file_size_mapped += (getsize(filename) )

			index_buffer = 0
			with open(filename,'rb') as read_data:
				x = np.array(list(read_data.read(10240)))
				x_copy_for_chunk_insertion = deepcopy(x)
				x = self.pad_to_byte_shape(x)
				x = np.concatenate([ self.pad_to_byte_shape(np.append(x,np.zeros(shape=[data]))) for data in np.arange(self.max_tags-1)])
				

				
				#x = np.append(x,(np.ones(self.max_tags - (x.shape[0] % self.max_tags) )*self.max_tags)).reshape(-1,1,self.max_tags)
				#print(filename)
				
				

				found_values = (x == self.tags_bytes.reshape(1,-1,self.max_tags)).astype(np.int32).sum(axis=-1)
				
				# [is_found,NEAR POS]
				storage = int(found_values.argmax() / (self.max_tags-1))
				
				
				try:
					x = np.append(x[storage-10:storage+10],[])
					pad_size = np.arange(x.size)
					x = bytes(np.append(np.zeros(shape=[0]),x))
					#			print(x.decode('utf-8'))

					if (found_values.max() > 0):

						print(x.decode('utf-16'))
						op_cond_found = True

					else:

						# import pdb; pdb.set_trace()
						indexs_overwrite = np.append(indexs_overwrite,x_copy_for_chunk_insertion)
						index_buffer += 1
						#			x = np.append(x,
						#			y = [ self.byte_decode_match_zero_non_error(data)  for data in np.arange(x.size) ]
					#encoded_sizes = pad_size[np.array([ self.byte_decode_match_zero_non_error(data)  for data in np.arange(x.size) ]).astype(np.bool_)]
				except:
					import pdb; pdb.set_trace()
							
				
				found_values_return = np.concatenate(found_values_return,np.array([found_values.max() > 0,int(found_values.argmax() / (self.max_tags-1))]))


			index_buffer = 0

			zeros = np.zeros(10240)


			if (op_cond_found):
				self.op_insert_removeal(filename,indexs_overwrite)



				





		except:
			# import pdb; pdb.set_trace()

			indexs_overwrite = np.append(indexs_overwrite,x_copy_for_chunk_insertion)

			with open('failed_list.txt','a',encoding='utf-8') as write_data: write_data.write(filename+"\n")


			if (op_cond_found):
				self.op_insert_removeal(filename,indexs_overwrite)

			return np.array([0,0])
		
		return found_values_return

			

			
	def file_search(self,x):
		

                
		vec = np.vectorize(self.op_read,signature='()->(2)')(x)
		try:
			self.found_files = np.unique(np.append(self.found_files,x[vec[:,0]]))
		except:
			pass
			
			

		
	def add_path(self,new_level,file_path):
	
		if (file_path == '/'):
			file_path = ''

	
		new_level = np.array((f' {file_path}/'.join(np.append([' '],new_level)))[1:].split(" "))
		new_level = new_level[new_level != '']
		return new_level
	
	
	def search_current(self):
	
#		system('clear')
			

		

		if (self.file_size_mapped/1e9 > 1000):
			import pdb; pdb.set_trace()

		print(self.storage_used/1e9,self.file_size_mapped/1e9)

		system('clear')

		print("\n\n\n------Firewall Command Scanner KILLBOT 0.2V------\n\n")
		
		print('Linux Machine Mapped (%)',np.round(self.file_size_mapped / self.storage_used,8)*100)
		print("Found Files",self.found_files.size)
		# np.save("cashed_firewall_targets_found.npy",self.found_files)
		# print('Found',self.found_files)


	
	def search_now(self,file_path,dirs):
	
		
		#print(file_path)
		
		
		
		try:
			x = next(walk(file_path))			
		except:
			try:
				self.lost = np.array(self.lost,file_path)
			except:
				return dirs 

		

		#import pdb; pdb.set_trace()

		
		dirs = np.append(dirs,self.add_path(np.array(x[1]).astype(np.str_),file_path))

		try:		
			state = self.add_path(np.array(x[2]).astype(np.str_),file_path)
		except:
			import pdb; pdb.set_trace()
		if (state.size != 0):

			self.file_search(state)
			

		
		return dirs
		
	
	
	
	def port_reg_ex(self,data):
		return f'[^0-9]+{data}([^0-9])+'
		



class dirs_vec:



	def __init__(self):


		try:
			ext = argv[1]
		except:
			ext = '/'	
	
		self.dirs = np.array([ext])
		self.search_obj = search_for_file_ext()

	
	

		
	def search_now(self):
	
		


		file_size = 0
		while self.dirs.size != 0:
			
			#print(self.search_obj.found_files.size)
			
			

			self.dirs = self.search_obj.search_now(self.dirs[0],self.dirs)
			self.dirs = self.dirs[1:]
				
	
			
			
			
			

if (__name__ == "__main__"):

	dirs_vec().search_now()
		
		
