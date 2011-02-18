FILE_LIST=build/INSTALLED_FILES

# build only
all:
	python setup.py build    

# install scs module making sure files are readable by everone
install:
	@python setup.py install -f --record ${FILE_LIST}; \
	[ -s ${FILE_LIST} ] && find `cat ${FILE_LIST}` -exec chmod a+r {} \;

clean:
	python setup.py clean    
