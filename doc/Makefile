TCLSH = /usr/bin/tclsh
XML2RFC = xml2rfc.tcl

XML = draft-scs.xml
TXT = $(XML:.xml=.txt)
HTML = $(XML:.xml=.html)

all: $(TXT) $(HTML)

%.txt:  %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@
%.html: %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@

clean: ; $(RM) $(TXT) $(HTML)
