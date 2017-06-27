#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(84044);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2015-5522", "CVE-2015-5523");

  script_name(english:"FreeBSD : tidy -- heap-buffer-overflow (bd1ab7a5-0e01-11e5-9976-a0f3c100ae18)");
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
"Geoff McLane reports :

tidy is affected by a write out of bounds when processing malformed
html files.

This issue could be abused on server side applications that use
php-tidy extension with user input.

The issue was confirmed, analysed and fixed by the tidy5 maintainer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/htacg/tidy-html5/issues/217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2015/q2/633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2015/q3/116"
  );
  # http://www.freebsd.org/ports/portaudit/bd1ab7a5-0e01-11e5-9976-a0f3c100ae18.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?196a1124"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tidy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tidy-html5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tidy-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tidy4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"tidy4<=20000804_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tidy-devel<=090315.c_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tidy-lib<=090315.c_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tidy-html5<4.9.31")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
