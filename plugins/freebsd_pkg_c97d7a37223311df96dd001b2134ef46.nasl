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
  script_id(44922);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2006-4339", "CVE-2009-0217", "CVE-2009-2493", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");

  script_name(english:"FreeBSD : openoffice.org -- multiple vulnerabilities (c97d7a37-2233-11df-96dd-001b2134ef46)");
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
"OpenOffice.org Security Team reports :

Fixed in OpenOffice.org 3.2

CVE-2006-4339: Potential vulnerability from 3rd party libxml2
libraries

CVE-2009-0217: Potential vulnerability from 3rd party libxmlsec
libraries

CVE-2009-2493: OpenOffice.org 3 for Windows bundles a vulnerable
version of MSVC Runtime

CVE-2009-2949: Potential vulnerability related to XPM file processing

CVE-2009-2950: Potential vulnerability related to GIF file processing

CVE-2009-3301/2: Potential vulnerability related to MS-Word document
processing"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/bulletin.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2006-4339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2949.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-2950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/cves/CVE-2009-3301-3302.html"
  );
  # http://www.freebsd.org/ports/portaudit/c97d7a37-2233-11df-96dd-001b2134ef46.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a74e5e58"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"openoffice.org<3.2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice.org>=3.2.20010101<3.2.20100203")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openoffice.org>=3.3.20010101<3.3.20100207")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
