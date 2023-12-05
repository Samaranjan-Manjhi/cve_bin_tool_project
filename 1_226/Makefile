#all : selfprotection sprem spmov spremd spshowmutable spsetmutable

#SP_INCLUDE=-Iheader -I../libmwshare/header/ -I../sfl -I../libescan/header -I../scan_module/include 

LFLAGS=-Wl,-rpath=/opt/MicroWorld/lib/ 
#INSTALLPATH=/opt/MicroWorld/lib

#LIBS=/opt/MicroWorld/lib/libmwshare.so.1.0.0 /opt/MicroWorld/lib/libmwact.so.1.0.0 /opt/MicroWorld/lib/libmwsusp.so.1.0.0 /opt/MicroWorld/lib/libmwdmidecode.so  /opt/MicroWorld/lib/libescan.so.3.0.0 /opt/MicroWorld/lib/libcrypto.so.0.9.8 
LIBS=/opt/MicroWorld/lib/libmwshare.so.1.0.0 /opt/MicroWorld/lib/libmwact.so.1.0.0 /opt/MicroWorld/lib/libmwsusp.so.1.0.0 /opt/MicroWorld/lib/libmwdmidecode.so  /opt/MicroWorld/lib/libescan.so.3.0.0 /opt/MicroWorld/lib/libssl.so.0.9.8  /opt/MicroWorld/lib/libcurl.so.4  /opt/MicroWorld/lib/libcrypto.so.0.9.8  

# /opt/MicroWorld/lib/libcrypto.so.4 #-lcrypto #/opt/MicroWorld/lib/libcrypto.so.0.9.8 #/opt/Microworld/lib/libzip.so #/opt/MicroWorld/lib/libcrypto.so.4

#final:
all:
	@echo compiling soure code!!!
	@echo "wait for sometimes!!!"
	g++ data_dist.cpp -DZIP_STD  ${SP_INCLUDE} -Wl,-rpath=/opt/Microworld/lib/ -ldl ${LIBS} -o vulCatcher -lpthread -lsqlite3 #-lzip

