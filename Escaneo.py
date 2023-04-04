#!/usr/bin/python3

import nmap

print(" __                 ")
print("'. \                ")
print(" '- \               ")
print("  / /_         .---.")
print(" / | \\,.\/--.//    )")
print(" |  \//        )/  / ")
print("  \  ' ^ ^    /    )____.----..  6")
print("   '.____.    .___/            \._)")
print("      .\/.                      )")
print("       '\                       /")
print("       _/ \/    ).        )    (")
print("      /#  .!    |        /\    /")
print("      \  C// #  /'-----''/ #  /")
print("   .   'C/ |    |    |   |    |mrf  ,")
print("   \), .. .'OOO-'. ..'OOO'OOO-'. ..\(,")


ip = input("[+] Introduce la dirección IP: ")

nm = nmap.PortScanner()

results = nm.scan(hosts=ip, arguments="-sS -O -A -sV") 
print("Host : %s" % ip)
print("State : %s" % nm[ip].state())

if 'osmatch' in nm[ip]:
    for osmatch in nm[ip]['osmatch']:
        print('[+] Sistema Operativo : %s' % osmatch['name'])

for proto in nm[ip].all_protocols():
    print('Protocol : %s' % proto)
    lport = nm[ip][proto].keys()
    sorted(lport)
    for port in lport:
        print('port : %s\tstate: %s' % (port, nm[ip][proto][port]['state']))
        print("Nombre del servicio: %s" % nm[ip][proto][port]['name'])
        print("Producto: %s" % nm[ip][proto][port]['product'])
        print("Version: %s" % nm[ip][proto][port]['version'])
        print("OS: %s" % nm[ip]['osmatch'][0]['name'])


