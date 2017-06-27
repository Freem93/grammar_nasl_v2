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
  script_id(85428);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/29 14:44:44 $");

  script_cve_id("CVE-2013-7444", "CVE-2015-6727", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2015-6731", "CVE-2015-6733", "CVE-2015-6734", "CVE-2015-6735", "CVE-2015-6736", "CVE-2015-6737");

  script_name(english:"FreeBSD : mediawiki -- multiple vulnerabilities (6241b5df-42a1-11e5-93ad-002590263bf5)");
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
"MediaWiki reports :

Internal review discovered that Special:DeletedContributions did not
properly protect the IP of autoblocked users. This fix makes the
functionality of Special:DeletedContributions consistent with
Special:Contributions and Special:BlockList.

Internal review discovered that watchlist anti-csrf tokens were not
being compared in constant time, which could allow various timing
attacks. This could allow an attacker to modify a user's watchlist via
csrf

John Menerick reported that MediaWiki's thumb.php failed to sanitize
various error messages, resulting in xss."
  );
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-August/000179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf7cba99"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T106893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T94116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://phabricator.wikimedia.org/T97391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2015/08/27/6"
  );
  # http://www.freebsd.org/ports/portaudit/6241b5df-42a1-11e5-93ad-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c259ee3f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki125");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");
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

if (pkg_test(save_report:TRUE, pkg:"mediawiki123<1.23.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki124<1.24.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mediawiki125<1.25.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
