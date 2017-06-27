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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66798);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/21 23:48:18 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1993", "CVE-2013-1994", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066");

  script_name(english:"FreeBSD : xorg -- protocol handling issues in X Window System client libraries (2eebebff-cd3b-11e2-8f09-001b38c3836c)");
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
"freedesktop.org reports :

Ilja van Sprundel, a security researcher with IOActive, has discovered
a large number of issues in the way various X client libraries handle
the responses they receive from servers, and has worked with X.Org's
security team to analyze, confirm, and fix these issues.

Most of these issues stem from the client libraries trusting the
server to send correct protocol data, and not verifying that the
values will not overflow or cause other damage. Most of the time X
clients & servers are run by the same user, with the server more
privileged from the clients, so this is not a problem, but there are
scenarios in which a privileged client can be connected to an
unprivileged server, for instance, connecting a setuid X client (such
as a screen lock program) to a virtual X server (such as Xvfb or
Xephyr) which the user has modified to return invalid data,
potentially allowing the user to escalate their privileges.

The vulnerabilities include :

Integer overflows calculating memory needs for replies.

Sign extension issues calculating memory needs for replies.

Buffer overflows due to not validating length or offset values in
replies.

Integer overflows parsing user-specified files.

Unbounded recursion parsing user-specified files.

Memory corruption due to unchecked return values."
  );
  # http://www.freebsd.org/ports/portaudit/2eebebff-cd3b-11e2-8f09-001b38c3836c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00e99369"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libFS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXinerama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXxf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xf86-video-openchrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"libX11<1.6.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXext<1.3.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXfixes<5.0.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXi<1.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXinerama<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXp<1.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXrandr<1.4.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXrender<0.9.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXres<1.0.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXtst<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXv<1.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXvMC<1.0.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXxf86dga<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libdmx<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxcb<1.9.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libGL<7.6.1_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libGL>7.8.0<8.0.5_4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xf86-video-openchrome<0.3.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libFS<1.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXxf86vm<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXt<1.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXcursor<1.1.14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
