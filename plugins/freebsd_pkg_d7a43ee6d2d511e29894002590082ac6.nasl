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
  script_id(66875);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/11 10:42:54 $");

  script_cve_id("CVE-2013-2039", "CVE-2013-2040", "CVE-2013-2041", "CVE-2013-2042", "CVE-2013-2043", "CVE-2013-2044", "CVE-2013-2045", "CVE-2013-2047", "CVE-2013-2048", "CVE-2013-2085", "CVE-2013-2086", "CVE-2013-2089", "CVE-2013-2149", "CVE-2013-2150");

  script_name(english:"FreeBSD : owncloud -- Multiple security vulnerabilities (d7a43ee6-d2d5-11e2-9894-002590082ac6)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ownCloud development team reports :

oC-SA-2013-019 / CVE-2013-2045: Multiple SQL Injections. Credit to
Mateusz Goik (aliantsoft.pl).

oC-SA-2013-020 / CVE-2013-[2039,2085]: Multiple directory traversals.
Credit to Mateusz Goik (aliantsoft.pl).

oC-SQ-2013-021 / CVE-2013-[2040-2042]: Multiple XSS vulnerabilities.
Credit to Mateusz Goik (aliantsoft.pl) and Kacper R.
(http://devilteam.pl).

oC-SA-2013-022 / CVE-2013-2044: Open redirector. Credit to Mateusz
Goik (aliantsoft.pl).

oC-SA-2013-023 / CVE-2013-2047: Password autocompletion.

oC-SA-2013-024 / CVE-2013-2043: Privilege escalation in the calendar
application. Credit to Mateusz Goik (aliantsoft.pl).

oC-SA-2013-025 / CVE-2013-2048: Privilege escalation and CSRF in the
API.

oC-SA-2013-026 / CVE-2013-2089: Incomplete blacklist vulnerability.

oC-SA-2013-027 / CVE-2013-2086: CSRF token leakage.

oC-SA-2013-028 / CVE-2013-[2149-2150]: Multiple XSS vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-019/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-020/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-021/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-022/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-023/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-024/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-025/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-026/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-027/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://owncloud.org/about/security/advisories/oC-SA-2013-028/"
  );
  # http://www.freebsd.org/ports/portaudit/d7a43ee6-d2d5-11e2-9894-002590082ac6.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad07b877"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:owncloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"owncloud<5.0.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
