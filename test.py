b = dict()
a = dict()
a['party'] = "A"
b['party'] = 'B'

c = []
c.append(a['party'])
c.append(b['party'])
c.append('A')
print(c.count('B'))
