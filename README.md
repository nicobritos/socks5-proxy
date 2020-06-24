# TPE - Protocolos de comunicacion - 1Q2020 - Grupo 6

## Archivos

* El Informe se encuentra en `/Informe.pdf`
* La descripcion del protocolo se enccuentra en `/RFC.txt`
* Los archivos para correspondientes al servidor se encuentran en `/src/`
* Los archivos para correspondientes al cliente se encuentran en  `/monitor/`
* Los archivos para correspondientes al cliente se encuentran en  `/monitor/`
* En `/src/` se encuentran los archivos `.dot` correspondientes a las maquinas de estados de los parsers. 

## Compilacion

`
cmake CMakeLists.txt
make
`
El comando make genera el ejecutable del servidor y del cliente. 

## Ejemplo Ejecucion

`./PC-2020A-6-TPE.SOCKSV5 -l 127.0.0.1 --doh-port 80 -u root:root

./monitor_client
`

