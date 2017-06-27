#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(99554);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2017-7585", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742");

  script_name(english:"FreeBSD : libsndfile -- multiple vulnerabilities (5a97805e-93ef-4dcb-8d5e-dbcac263bfc2)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NVD reports :

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a stack-based buffer
overflow via a specially crafted FLAC file.

In libsndfile before 1.0.28, an error in the 'header_read()' function
(common.c) when handling ID3 tags can be exploited to cause a
stack-based buffer overflow via a specially crafted FLAC file.

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a segmentation violation
(with write memory access) via a specially crafted FLAC file during a
resample attempt, a similar issue to CVE-2017-7585.

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a segmentation violation
(with read memory access) via a specially crafted FLAC file during a
resample attempt, a similar issue to CVE-2017-7585."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/commit/60b234301adf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/commit/708e996c87c5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/commit/f457b7b5ecfe"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/commit/60b234301adf"
  );
  # http://www.freebsd.org/ports/portaudit/5a97805e-93ef-4dcb-8d5e-dbcac263bfc2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ce309ee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-libsndfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"libsndfile<1.0.28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-libsndfile<1.0.28")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-libsndfile<1.0.28")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
