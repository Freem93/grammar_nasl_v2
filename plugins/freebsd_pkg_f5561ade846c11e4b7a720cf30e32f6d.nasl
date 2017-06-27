#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(80039);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/19 15:10:36 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108");

  script_name(english:"FreeBSD : subversion -- DoS vulnerabilities (f5561ade-846c-11e4-b7a7-20cf30e32f6d)");
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
"Subversion Project reports :

Subversion's mod_dav_svn Apache HTTPD server module will crash when it
receives a REPORT request for some invalid formatted special URIs.

Subversion's mod_dav_svn Apache HTTPD server module will crash when it
receives a request for some invalid formatted special URIs.

We consider this to be a medium risk vulnerability. Repositories which
allow for anonymous reads will be vulnerable without authentication.
Unfortunately, no special configuration is required and all
mod_dav_svn servers are vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-3580-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-8108-advisory.txt"
  );
  # http://www.freebsd.org/ports/portaudit/f5561ade-846c-11e4-b7a7-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d3af260"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mod_dav_svn>=1.8.0<1.8.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion16>=1.0.0<1.7.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion17>=1.0.0<1.7.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion>=1.0.0<1.7.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion>=1.8.0<1.8.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
