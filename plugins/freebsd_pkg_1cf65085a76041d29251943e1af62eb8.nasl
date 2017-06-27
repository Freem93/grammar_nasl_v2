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
  script_id(93933);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-5407");

  script_name(english:"FreeBSD : X.org libraries -- multiple vulnerabilities (1cf65085-a760-41d2-9251-943e1af62eb8)");
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
"Matthieu Herrb reports :

Tobias Stoeckmann from the OpenBSD project has discovered a number of
issues in the way various X client libraries handle the responses they
receive from servers, and has worked with X.Org's security team to
analyze, confirm, and fix these issues. These issue come in addition
to the ones discovered by Ilja van Sprundel in 2013.

Most of these issues stem from the client libraries trusting the
server to send correct protocol data, and not verifying that the
values will not overflow or cause other damage. Most of the time X
clients and servers are run by the same user, with the server more
privileged than the clients, so this is not a problem, but there are
scenarios in which a privileged client can be connected to an
unprivileged server, for instance, connecting a setuid X client (such
as a screen lock program) to a virtual X server (such as Xvfb or
Xephyr) which the user has modified to return invalid data,
potentially allowing the user to escalate their privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.x.org/archives/xorg-announce/2016-October/002720.html"
  );
  # http://www.freebsd.org/ports/portaudit/1cf65085-a760-41d2-9251-943e1af62eb8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7a7dbd7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libXvMC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");
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

if (pkg_test(save_report:TRUE, pkg:"libX11<1.6.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXfixes<5.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXi<1.7.7,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXrandr<1.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXrender<0.9.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXtst<1.2.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXv<1.0.11,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libXvMC<1.0.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
