include .config
NAME-LINK=$(subst _,-,$(NAME))

ESCAPED-BUILDDIR = $(shell echo '$(BUILDDIR)' | sed 's%/%\\/%g')
SRCS=$(wildcard *.nim)
TARGET=$(SRCS:%.nim=$(BUILDDIR)/htmldocs/%.html)
BUILDSCRIPTS=$(NAME).nimble
DSTSCRIPTS=$(BUILDSCRIPTS:%=$(BUILDDIR)/%)
DSTSRCS=$(SRCS:%=$(BUILDDIR)/%)

all: $(TARGET)

install: $(DSTSRCS) $(DSTSCRIPTS)
	cd $(BUILDDIR); nimble install; cd -

$(TARGET): $(BUILDDIR)/htmldocs/%.html: $(BUILDDIR)/%.nim
	cd $(BUILDDIR); nim doc $(notdir $<); cd -

$(DSTSCRIPTS): $(BUILDDIR)/%: % | prebuild
	cp $< $@

$(DSTSRCS): $(BUILDDIR)/%: % .config | prebuild
	sed 's/%%BUILDDIR%%/$(ESCAPED-BUILDDIR)/g' $< | \
	sed 's/%%NAME%%/$(NAME)/g' | \
	sed 's/%%NAME-LINK%%/$(NAME-LINK)/g' | \
	sed '/^ *info /s|$$|; flush_file(stdout)|' > $@

prebuild:
ifeq "$(wildcard $(BUILDDIR))" ""
	@mkdir -p $(BUILDDIR)
endif

clean:
	rm -rf $(BUILDDIR)

.PHONY: all clean install prebuild
