## Process this file with automake to produce Makefile.in

# versiondir = $(prefix)/etc
# dist_version_DATA = VERSION
# chown = @CHOWN@

# testing removed for the moment 
SUBDIRS = src
# DIST_SUBDIRS = src policy local tools
# EXTRA_DIST = README VERSION
EXTRA_DIST = policy local-policy tools

test:
	( cd testing && $(MAKE) test )

docs:
	( cd doc && $(MAKE) doc )

doc-install:
	( cd doc && $(MAKE) doc-install )

# make sure we don't leak cvs or priv policy files
dist-hook:
	cp $(srcdir)/policy/*.anon $(distdir)/policy/
	cp $(srcdir)/local-policy-sample/*.anon $(distdir)/local-policy/
	cp -r $(srcdir)/tools/* $(distdir)/tools/
	rm -rf `find $(distdir) -name CVS`

# make sure all the dirs are correctly created and owned 
install-data-local:
	$(INSTALL) -d $(prefix)/logs
	$(INSTALL) -d $(prefix)/archive
	$(INSTALL) -d $(prefix)/var

release:
	./autogen.sh
	./configure
	$(MAKE) distcheck
