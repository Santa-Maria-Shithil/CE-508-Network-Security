fp = open('./output.txt','r')
file_reader = fp.read().strip()
file_lines = file_reader.split('\n')
pkt_dict = {}
for line_ in file_lines:
    sub = (line_[line_.find('length ')+len('length '):])
    length_ = int(sub[:sub.find(':')])
    if length_ in pkt_dict:
        pkt_dict[length_] += 1
    else:
        pkt_dict[length_] = 1
print ('Packet_Size\t No. of Occurrences')
sorted_dict = dict(sorted(pkt_dict.items()))

for key in sorted_dict:
    print (key,'\t\t',sorted_dict[key])
