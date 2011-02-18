TCLSH = /usr/bin/tclsh
XML2RFC = xml2rfc.tcl
XSLTPROC = /usr/bin/xsltproc
XSLT = rfc2629.xslt

XML = draft-scs.xml
TXT = $(XML:.xml=.txt)
HTML = $(XML:.xml=.html)

all: $(TXT) $(HTML)

%.txt:  %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@
%.html: %.xml
	$(XSLTPROC) --param xml2rfc-toc '"yes"' \
		--param xml2rfc-ext-support-rfc2731 '"no"' \
		$(XSLT) $< > $@

clean: ; $(RM) $(TXT) $(HTML)
