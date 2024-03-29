#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2020 Joyent, Inc.
# Copyright 2023 MNX Cloud, Inc.
#

RUST_TOOLCHAIN = 1.40.0

# Rust < 1.49 must specify sun-solaris target:
RUST_BOOTSTRAP_TARGET=x86_64-sun-solaris

#
# Files
#
DOC_FILES =		index.md
JSON_FILES :=		package.json


# While this component doesn't require a base image, we set this so
# that validate-buildenv can determine whether we're building on
# a recent enough image (including a reasonably recent version of rust)
# triton-origin-x86_64-19.4.0
BASE_IMAGE_UUID = 59ba2e5e-976f-4e09-8aac-a4a7ef0395f5

#
# Makefile.defs defines variables used as part of the build process.
# Ensure we have the eng submodule before attempting to include it.
#
ENGBLD_REQUIRE := $(shell git submodule update --init deps/eng)
include ./deps/eng/tools/mk/Makefile.defs
include ./deps/eng/tools/mk/Makefile.rust.defs

TOP ?= $(error Unable to access eng.git submodule Makefiles.)

NAME :=			firewall-logger-agent
RELEASE_TARBALL :=	$(NAME)-$(STAMP).tgz
RELEASE_MANIFEST :=	$(NAME)-$(STAMP).manifest
RELSTAGEDIR :=		/tmp/$(NAME)-$(STAMP)

DISTCLEAN_FILES += $(NAME)-*.manifest $(NAME)-*.tgz

#
# Repo-specific targets
#
.PHONY: all
all: $(SMF_MANIFESTS) $(CARGO_TARGET_DIR)/release/cfwlogd | $(REPO_DEPS)

debug: $(CARGO_TARGET_DIR)/debug/cfwlogd
$(CARGO_TARGET_DIR)/debug/cfwlogd: $(RS_FILES) | $(CARGO_EXEC)
	$(CARGO) build

$(CARGO_TARGET_DIR)/release/cfwlogd: $(RS_FILES) | $(CARGO_EXEC)
	$(CARGO) build --release

.PHONY: test
test: test-unit

.PHONY: test-unit
test-unit:
	$(CARGO) test

.PHONY: release
release: all
	echo "Building $(RELEASE_TARBALL)"
	mkdir -p $(TOP)/bin
	cp $(TOP)/target/release/cfwlogd \
		$(TOP)/bin/cfwlogd
	mkdir -p $(RELSTAGEDIR)/$(NAME)
	cp -r \
	    $(TOP)/bin \
	    $(TOP)/npm \
	    $(TOP)/smf \
	    $(TOP)/deps/eng/tools \
	    $(RELSTAGEDIR)/$(NAME)
	json -f $(TOP)/package.json -e 'this.version += "-$(STAMP)"' \
	    > $(RELSTAGEDIR)/$(NAME)/package.json
	uuid -v4 >$(RELSTAGEDIR)/$(NAME)/image_uuid
	cd $(RELSTAGEDIR) && $(TAR) -I pigz -cf $(TOP)/$(RELEASE_TARBALL) *
	cat $(TOP)/manifest.tmpl | sed \
	    -e "s/UUID/$$(cat $(RELSTAGEDIR)/$(NAME)/image_uuid)/" \
	    -e "s/NAME/$$(json name < $(TOP)/package.json)/" \
	    -e "s/VERSION/$$(json version < $(TOP)/package.json)/" \
	    -e "s/DESCRIPTION/$$(json description < $(TOP)/package.json)/" \
	    -e "s/BUILDSTAMP/$(STAMP)/" \
	    -e "s/SIZE/$$(stat --printf="%s" $(TOP)/$(RELEASE_TARBALL))/" \
	    -e "s/SHA/$$(openssl sha1 $(TOP)/$(RELEASE_TARBALL) \
	    | cut -d ' ' -f2)/" \
	    > $(TOP)/$(RELEASE_MANIFEST)
	rm -rf $(RELSTAGEDIR)

.PHONY: publish
publish: release
	mkdir -p $(ENGBLD_BITS_DIR)/$(NAME)
	cp $(TOP)/$(RELEASE_TARBALL) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_TARBALL)
	cp $(TOP)/$(RELEASE_MANIFEST) $(ENGBLD_BITS_DIR)/$(NAME)/$(RELEASE_MANIFEST)

# Here "cutting a release" is just tagging the current commit with
# "v(package.json version)". We don't publish this to npm.
.PHONY: cutarelease
cutarelease:
	echo "# Ensure working copy is clean."
	[[ -z `git status --short` ]]  # If this fails, the working dir is dirty.
	echo "# Ensure have 'json' tool."
	which json 2>/dev/null 1>/dev/null
	ver=$(shell cat package.json | json version) && \
	    git tag "v$$ver" && \
	    git push origin "v$$ver"

include ./deps/eng/tools/mk/Makefile.deps
include ./deps/eng/tools/mk/Makefile.targ
include ./deps/eng/tools/mk/Makefile.rust.targ
