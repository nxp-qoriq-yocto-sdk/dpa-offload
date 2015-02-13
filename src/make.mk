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

# The sub-component library name
LIBNAME = libdpa-offload.a
LIBS += $(LIBNAME)

# The sub-component objects
OBJS = dpa_classifier.o

ABS_OBJS := $(foreach obj,$(OBJS),$(addprefix $(SRC_SUBDIR)/,$(obj)))
OBJECTS += $(ABS_OBJS)

# Library interface (files to install)
ABS_INTERFACE += include/fsl_dpa_offload.h \
	include/fsl_dpa_classifier.h

# Specific build flags for this sub-component
BUILDFLAGS += $(USDPAA_CFLAGS)

# Library dependencies (rule)
$(OUTDIR)/$(LIBNAME): $(ABS_OBJS)

ABS_DEPS := $(foreach objfile,$(ABS_OBJS),$(subst .o,.dep,$(objfile)))

# Create rules & recipes for sub-component dependency files
$(eval $(call add_dep_recipe,$(ABS_DEPS),$(BUILDFLAGS)))

# Include sub-component dependency files (object rules)
include $(ABS_DEPS)

# Create sub-component build recipes
$(eval $(call add_build_recipe,$(ABS_OBJS),$(BUILDFLAGS)))

# Create sub-component library recipe
$(eval $(call add_lib_recipe,$(LIBNAME),$(ABS_OBJS)))
