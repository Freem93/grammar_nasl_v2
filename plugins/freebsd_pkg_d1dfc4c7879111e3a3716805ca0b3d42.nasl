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
  script_id(72155);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/16 10:38:57 $");

  script_cve_id("CVE-2014-1474");

  script_name(english:"FreeBSD : rt42 -- denial-of-service attack via the email gateway (d1dfc4c7-8791-11e3-a371-6805ca0b3d42)");
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
"The RT development team reports :

Versions of RT between 4.2.0 and 4.2.2 (inclusive) are vulnerable to a
denial-of-service attack via the email gateway; any installation which
accepts mail from untrusted sources is vulnerable, regardless of the
permissions configuration inside RT. This vulnerability is assigned
CVE-2014-1474.

This vulnerability is caused by poor parsing performance in the
Email::Address::List module, which RT depends on. We recommend that
affected users upgrade their version of Email::Address::List to v0.02
or above, which resolves the issue. Due to a communications mishap,
the release on CPAN will temporarily appear as 'unauthorized,' and the
command-line cpan client will hence not install it. We expect this to
be resolved shortly; in the meantime, the release is also available
from our server."
  );
  # http://blog.bestpractical.com/2014/01/security-vulnerability-in-rt-42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c21c8430"
  );
  # http://www.freebsd.org/ports/portaudit/d1dfc4c7-8791-11e3-a371-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2650755d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:p5-Email-Address-List");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt42");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");
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

if (pkg_test(save_report:TRUE, pkg:"rt42>=4.2<4.2.1_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rt42>=4.2.2<4.2.2_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"p5-Email-Address-List<0.02")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
