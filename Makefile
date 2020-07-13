obj-m += sauron.o
sauron-y += src/entry.o src/utils.o src/arch.o src/vmm.o src/vmx.o src/vmcs.o src/vmxasm.o src/cpu.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
