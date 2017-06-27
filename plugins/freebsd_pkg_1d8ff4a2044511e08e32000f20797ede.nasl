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
  script_id(51132);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/13 14:37:08 $");

  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (1d8ff4a2-0445-11e0-8e32-000f20797ede)");
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
"The Mozilla Project reports :

MFSA 2010-74 Miscellaneous memory safety hazards (rv:1.9.2.13/
1.9.1.16)

MFSA 2010-75 Buffer overflow while line breaking after document.write
with long string

MFSA 2010-76 Chrome privilege escalation with window.open and isindex
element

MFSA 2010-77 Crash and remote code execution using HTML tags inside a
XUL tree

MFSA 2010-78 Add support for OTS font sanitizer

MFSA 2010-79 Java security bypass from LiveConnect loaded via data:
URL meta refresh

MFSA 2010-80 Use-after-free error with nsDOMAttribute MutationObserver

MFSA 2010-81 Integer overflow vulnerability in NewIdArray

MFSA 2010-82 Incomplete fix for CVE-2010-0179

MFSA 2010-83 Location bar SSL spoofing using network error page

MFSA 2010-84 XSS hazard in multiple character encodings"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-74.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-75.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-76.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-77.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-78.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-79.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-80.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-81.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-82.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-83.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-84.html"
  );
  # http://www.freebsd.org/ports/portaudit/1d8ff4a2-0445-11e0-8e32-000f20797ede.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85f202a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox>3.6.*,1<3.6.13,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox>3.5.*,1<3.5.16,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>1.9.2.*<1.9.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<3.6.13,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox-devel<3.5.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey>2.0.*<2.0.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird>=3.1<3.1.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey>2.0.*<2.0.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=3.0<3.0.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=3.1<3.1.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
