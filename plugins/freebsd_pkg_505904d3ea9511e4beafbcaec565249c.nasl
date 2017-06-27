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
  script_id(83081);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/04/27 14:11:37 $");

  script_name(english:"FreeBSD : wordpress -- multiple vulnabilities (505904d3-ea95-11e4-beaf-bcaec565249c)");
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
"Gary Pendergast reports :

WordPress 4.1.2 is now available. This is a critical security release
for all previous versions and we strongly encourage you to update your
sites immediately.

WordPress versions 4.1.1 and earlier are affected by a critical
cross-site scripting vulnerability, which could enable anonymous users
to compromise a site. This was reported by Cedric Van Bockhaven and
fixed by Gary Pendergast, Mike Adams, and Andrew Nacin of the
WordPress security team.

We also fixed three other security issues :

- In WordPress 4.1 and higher, files with invalid or unsafe names
could be uploaded. Discovered by Michael Kapfer and Sebastian Kraemer
of HSASec.

- In WordPress 3.9 and higher, a very limited cross-site scripting
vulnerability could be used as part of a social engineering attack.
Discovered by Jakub Zoczek.

- Some plugins were vulnerable to a SQL injection vulnerability.
Discovered by Ben Bidner of the WordPress security team.

We also made four hardening changes, discovered by J.D. Grimes,
Divyesh Prajapati, Allan Collins, Marc-Alexandre Montpas and Jeff
Bowen."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wordpress.org/news/2015/04/wordpress-4-1-2/"
  );
  # http://www.freebsd.org/ports/portaudit/505904d3-ea95-11e4-beaf-bcaec565249c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fec71380"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-wordpress-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh-wordpress-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
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

if (pkg_test(save_report:TRUE, pkg:"wordpress<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress-zh_CN<4.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh-wordpress-zh_TW<4.1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
