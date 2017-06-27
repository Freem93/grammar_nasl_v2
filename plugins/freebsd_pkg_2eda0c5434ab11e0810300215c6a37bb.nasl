#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(51928);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/21 23:48:18 $");

  script_cve_id("CVE-2011-0450", "CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687");
  script_xref(name:"Secunia", value:"43023");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (2eda0c54-34ab-11e0-8103-00215c6a37bb)");
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
"Opera reports :

Opera 11.01 is a recommended upgrade offering security and stability
enhancements.

The following security vulnerabilities have been fixed :

- Removed support for 'javascript:' URLs in CSS -o-link values, to
make it easier for sites to filter untrusted CSS.

- Fixed an issue where large form inputs could allow execution of
arbitrary code, as reported by Jordi Chancel; see our advisory.

- Fixed an issue which made it possible to carry out clickjacking
attacks against internal opera: URLs; see our advisory.

- Fixed issues which allowed web pages to gain limited access to files
on the user's computer; see our advisory.

- Fixed an issue where email passwords were not immediately deleted
when deleting private data; see our advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/982/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/983/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/984/"
  );
  # http://www.freebsd.org/ports/portaudit/2eda0c54-34ab-11e0-8103-00215c6a37bb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f985fc52"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<11.01")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<11.01")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<11.01")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
