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
  script_id(82064);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/11 15:46:18 $");

  script_cve_id("CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503");

  script_name(english:"FreeBSD : GNU binutils -- multiple vulnerabilities (f6a014cd-d268-11e4-8339-001e679db764)");
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
"US-CERT/NIST reports :

The _bfd_XXi_swap_aouthdr_in function in bfd/peXXigen.c in GNU
binutils 2.24 and earlier allows remote attackers to cause a denial of
service (out-of-bounds write) and possibly have other unspecified
impact via a crafted NumberOfRvaAndSizes field in the AOUT header in a
PE executable.

US-CERT/NIST reports :

Heap-based buffer overflow in the pe_print_edata function in
bfd/peXXigen.c in GNU binutils 2.24 and earlier allows remote
attackers to cause a denial of service (crash) and possibly have other
unspecified impact via a truncated export table in a PE file.

US-CERT/NIST reports :

Stack-based buffer overflow in the ihex_scan function in bfd/ihex.c in
GNU binutils 2.24 and earlier allows remote attackers to cause a
denial of service (crash) and possibly have other unspecified impact
via a crafted ihex file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8503"
  );
  # http://www.freebsd.org/ports/portaudit/f6a014cd-d268-11e4-8339-001e679db764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b07d0b44"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cross-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:m6811-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:x86_64-pc-mingw32-binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"cross-binutils<2.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"x86_64-pc-mingw32-binutils<2.25")) flag++;
if (pkg_test(save_report:TRUE, pkg:"m6811-binutils<2.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
