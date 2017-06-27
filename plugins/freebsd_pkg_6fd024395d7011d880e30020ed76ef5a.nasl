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
  script_id(37025);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/08/09 10:50:38 $");

  script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");

  script_name(english:"FreeBSD : Several remotely exploitable buffer overflows in gaim (6fd02439-5d70-11d8-80e3-0020ed76ef5a)");
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
"Stefan Esser of e-matters found almost a dozen remotely exploitable
vulnerabilities in Gaim. From the e-matters advisory :

While developing a custom add-on, an integer overflow in the handling
of AIM DirectIM packets was revealed that could lead to a remote
compromise of the IM client. After disclosing this bug to the vendor,
they had to make a hurried release because of a change in the Yahoo
connection procedure that rendered GAIM useless. Unfourtunately at the
same time a closer look onto the sourcecode revealed 11 more
vulnerabilities.

The 12 identified problems range from simple standard stack overflows,
over heap overflows to an integer overflow that can be abused to cause
a heap overflow. Due to the nature of instant messaging many of these
bugs require man-in-the-middle attacks between client and server. But
the underlying protocols are easy to implement and MIM attacks on
ordinary TCP sessions is a fairly simple task.

In combination with the latest kernel vulnerabilities or the habit of
users to work as root/administrator these bugs can result in remote
root compromises."
  );
  # http://security.e-matters.de/advisories/012004.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdb6dd3c"
  );
  # http://www.freebsd.org/ports/portaudit/6fd02439-5d70-11d8-80e3-0020ed76ef5a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f3bf97b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ko-gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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

if (pkg_test(save_report:TRUE, pkg:"gaim<0.75_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gaim=0.75_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gaim=0.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-gaim<0.75_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-gaim=0.75_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-gaim=0.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-gaim<0.75_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-gaim=0.75_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ko-gaim=0.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-gaim<0.75_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-gaim=0.75_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-gaim=0.76")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gaim>=20030000")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
