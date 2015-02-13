# Copyright (c) 2015 Freescale Semiconductor, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
#
#
# ALTERNATIVELY, this software may be distributed under the terms of the
# GNU General Public License ("GPL") as published by the Free Software
# Foundation, either version 2 of that License or (at your option) any
# later version.
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

.PHONY: all install uninstall clean cleanobj cleandep help libs deps

# Default tools
CC ?= $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar rcs
RM ?= rm
CP ?= cp
ARCH ?= powerpc

CDEFINES = -D_GNU_SOURCE

CFLAGS := -Iinclude -pthread -O2 -Wall -Wshadow -Wstrict-prototypes \
	-Wwrite-strings -Wdeclaration-after-statement

# Adjust flags and directories according to platform
ifeq ($(ARCH),powerpc64)
	OUTDIR = lib_powerpc64
	LIBDESTSUBDIR = /usr/lib64
	CFLAGS += -mcpu=e500mc64 -m64
	CDEFINES += -D_FILE_OFFSET_BITS=64
else
	OUTDIR = lib_powerpc
	LIBDESTSUBDIR = /usr/lib
	CFLAGS += -mcpu=e500mc
endif

OBJECTS :=
LIBS :=
ABS_INTERFACE :=

INCDESTSUBDIR = /usr/include/dpa-offload
DESTDIR ?= $(shell pwd)/install

# Further subdirectories to search for Makefiles
SUBDIRS = src lib

# add_dep_recipe
#
# Creates a dependency recipe
# Arguments:
#	$(DEPFILELIST)
#	$(CFLAGS)
#
define add_dep_recipe
$(1): %.dep: %.c
	@echo "DEP $$<"
	@$$(CC) $(2) -MM -MT $$*.o -MF $$@ $$<
endef

# add_build_recipe
#
# Creates a build recipe
# Arguments:
#	$(OBJFILELIST)
#	$(CFLAGS)
#
define add_build_recipe
$(1): %.o: %.c %.dep
	@echo "CC $$<"
	@$$(CC) -c $(2) -o $$@ $$<
endef

# add_lib_recipe
#
# Creates a lib recipe
# Arguments:
#	$(LIBNAME)
#	$(OBJECTS)
#
define add_lib_recipe
$(OUTDIR)/$(1): | $(OUTDIR)
	@echo "AR $$@"
	@$$(AR) $$@ $(2)
endef

# include_sub_make
#
# Includes a sub Makefile from a specified subdirectory
# Arguments:
#	$(SUBDIR)
#	$(CFLAGS)
#
define include_sub_make
        $(eval SRC_SUBDIR := $(1))
        $(eval BUILDFLAGS := $(2))
        $(eval include $(1)/make.mk)
endef

all: libs

$(foreach dir,$(SUBDIRS),$(eval $(call include_sub_make,$(dir),$(CFLAGS))))

$(OUTDIR):
	@echo "Creating $(OUTDIR)..."
	@mkdir $(OUTDIR)

cleanobj:
	@echo "Cleaning up objects..."
	@for obj_name in $(shell echo $(OBJECTS)); \
	do \
		if [ -f $${obj_name} ] ;\
		then \
			echo "RM $${obj_name}" ;\
			$(RM) $${obj_name} ;\
		fi ;\
	done

cleandep:
	@echo "Cleaning up dependencies..."
	@for dep_name in $(shell echo $(foreach obj_name,$(OBJECTS),$(subst .o,.dep,$(obj_name)))); \
	do \
		if [ -f $${dep_name} ] ;\
		then \
			echo "RM $${dep_name}" ;\
			$(RM) $${dep_name} ;\
		fi ;\
	done

clean: cleanobj | $(OUTDIR)
	@echo "Cleaning up $(OUTDIR)..."
	@rm -rf $(OUTDIR)
	@mkdir $(OUTDIR)

ABS_LIBS = $(foreach libname,$(LIBS),$(addprefix $(OUTDIR)/,$(libname)))

libs: deps $(ABS_LIBS) | $(OUTDIR)

help:
	@echo
	@echo "Available targets:"
	@echo "	clean"
	@echo "	cleandep"
	@echo "	all"
	@echo "	dep"
	@echo "	install DESTDIR=..."
	@echo "	uninstall DESTDIR=..."
	@echo "	help"
	@for libname in $(shell echo $(ABS_LIBS)); \
	do \
		echo "	$${libname}" ;\
	done
	@echo

dep: $(foreach obj_name,$(OBJECTS),$(subst .o,.dep,$(obj_name)))

$(DESTDIR)$(INCDESTSUBDIR):
	@mkdir -p $(DESTDIR)$(INCDESTSUBDIR)

$(DESTDIR)$(LIBDESTSUBDIR):
	@mkdir -p $(DESTDIR)$(LIBDESTSUBDIR)

install: $(ABS_LIBS) | $(DESTDIR)$(INCDESTSUBDIR) $(DESTDIR)$(LIBDESTSUBDIR)
	@for file in $(shell echo $(ABS_INTERFACE)); \
	do \
		echo "INSTALL	$${file}" ;\
		$(CP) $${file} $(DESTDIR)$(INCDESTSUBDIR) ;\
	done
	@for file in $(shell echo $(ABS_LIBS)); \
	do \
		echo "INSTALL	$${file}" ;\
		$(CP) $${file} $(DESTDIR)$(LIBDESTSUBDIR) ;\
	done

uninstall:
	@for file in $(foreach fname,$(ABS_INTERFACE),$(notdir $(fname))); \
	do \
		echo "UNINSTALL	$${file}" ;\
		if [ -f $(DESTDIR)$(INCDESTSUBDIR)/$${file} ]; \
		then \
			$(RM) $(DESTDIR)$(INCDESTSUBDIR)/$${file} ;\
		fi \
	done
	@for file in $(shell echo $(LIBS)); \
	do \
		echo "UNINSTALL	$${file}" ;\
		if [ -f $(DESTDIR)$(LIBDESTSUBDIR)/$${file} ]; \
		then \
			$(RM) $(DESTDIR)$(LIBDESTSUBDIR)/$${file} ;\
		fi \
	done
