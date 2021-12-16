PACKAGE=flan_api

all: package
	
package:
	tar -czvf flan_api-$(BUILD_ENV)-$(BUILD_ID).tar.gz *
