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
  script_id(40508);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/22 00:10:41 $");

  script_cve_id("CVE-2009-2411");

  script_name(english:"FreeBSD : subversion -- heap overflow vulnerability (bce1f76d-82d0-11de-88ea-001a4d49522b)");
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
"A Subversion Security Advisory reports :

Subversion clients and servers have multiple heap overflow issues in
the parsing of binary deltas. This is related to an allocation
vulnerability in the APR library used by Subversion.

Clients with commit access to a vulnerable server can cause a remote
heap overflow; servers can cause a heap overflow on vulnerable clients
that try to do a checkout or update.

This can lead to a DoS (an exploit has been tested) and to arbitrary
code execution (no exploit tested, but the possibility is clear)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt"
  );
  # http://www.freebsd.org/ports/portaudit/bce1f76d-82d0-11de-88ea-001a4d49522b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e4184de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:p5-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion-freebsd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"subversion<1.6.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion-freebsd<1.6.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"p5-subversion<1.6.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py-subversion<1.6.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
