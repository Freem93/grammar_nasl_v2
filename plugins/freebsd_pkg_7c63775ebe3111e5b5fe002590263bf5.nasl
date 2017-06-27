#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(87984);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/08/10 13:36:30 $");

  script_cve_id("CVE-2013-0211", "CVE-2015-2304");
  script_xref(name:"FreeBSD", value:"SA-16:22.libarchive");
  script_xref(name:"FreeBSD", value:"SA-16:23.libarchive");

  script_name(english:"FreeBSD : libarchive -- multiple vulnerabilities (7c63775e-be31-11e5-b5fe-002590263bf5)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MITRE reports :

Integer signedness error in the archive_write_zip_data function in
archive_write_set_format_zip.c in libarchive 3.1.2 and earlier, when
running on 64-bit machines, allows context-dependent attackers to
cause a denial of service (crash) via unspecified vectors, which
triggers an improper conversion between unsigned and signed types,
leading to a buffer overflow.

Absolute path traversal vulnerability in bsdcpio in libarchive 3.1.2
and earlier allows remote attackers to write to arbitrary files via a
full pathname in an archive.

Libarchive issue tracker reports :

Using a crafted tar file bsdtar can perform an out-of-bounds memory
read which will lead to a SEGFAULT. The issue exists when the
executable skips data in the archive. The amount of data to skip is
defined in byte offset [16-19] If ASLR is disabled, the issue can lead
to an infinite loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/pull/110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/commit/5935715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/commit/2253154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/issues/502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/commit/3865cf2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/commit/e6c9668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libarchive/libarchive/commit/24f5de6"
  );
  # http://www.freebsd.org/ports/portaudit/7c63775e-be31-11e5-b5fe-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?510eaec3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libarchive");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"libarchive<3.1.2_5,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
