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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91939);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2016-5701", "CVE-2016-5702", "CVE-2016-5703", "CVE-2016-5704", "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5730", "CVE-2016-5731", "CVE-2016-5732", "CVE-2016-5733", "CVE-2016-5734", "CVE-2016-5739");

  script_name(english:"FreeBSD : phpMyAdmin -- multiple vulnerabilities (e7028e1d-3f9b-11e6-81f9-6805ca0b3d42)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The phpMYAdmin development team reports : Summary BBCode injection
vulnerability Description A vulnerability was discovered that allows
an BBCode injection to setup script in case it's not accessed on
https. Severity We consider this to be non-critical. Summary Cookie
attribute injection attack Description A vulnerability was found
where, under some circumstances, an attacker can inject arbitrary
values in the browser cookies. Severity We consider this to be
non-critical. Summary SQL injection attack Description A vulnerability
was discovered that allows a SQL injection attack to run arbitrary
commands as the control user. Severity We consider this vulnerability
to be serious Summary XSS on table structure page Description An XSS
vulnerability was discovered on the table structure page Severity We
consider this to be a serious vulnerability Summary Multiple XSS
vulnerabilities Description - An XSS vulnerability was discovered on
the user privileges page.

- An XSS vulnerability was discovered in the error console.

- An XSS vulnerability was discovered in the central columns feature.

- An XSS vulnerability was discovered in the query bookmarks feature.

- An XSS vulnerability was discovered in the user groups feature.
Severity We consider this to be a serious vulnerability Summary DOS
attack Description A Denial Of Service (DOS) attack was discovered in
the way phpMyAdmin loads some JavaScript files. Severity We consider
this to be of moderate severity Summary Multiple full path disclosure
vulnerabilities Description This PMASA contains information on
multiple full-path disclosure vulnerabilities reported in phpMyAdmin.

By specially crafting requests in the following areas, it is possible
to trigger phpMyAdmin to display a PHP error message which contains
the full path of the directory where phpMyAdmin is installed.

- Setup script

- Example OpenID authentication script Severity We consider these
vulnerabilities to be non-critical. Summary XSS through FPD
Description With a specially crafted request, it is possible to
trigger an XSS attack through the example OpenID authentication
script. Severity We do not consider this vulnerability to be secure
due to the non-standard required PHP setting for html_errors. Summary
XSS in partition range functionality Description A vulnerability was
reported allowing a specially crafted table parameters to cause an XSS
attack through the table structure page. Severity We consider this
vulnerability to be severe. Summary Multiple XSS vulnerabilities
Description - A vulnerability was reported allowing a specially
crafted table name to cause an XSS attack through the functionality to
check database privileges.

- This XSS doesn't exist in some translations due to different quotes
being used there (eg. Czech).

- A vulnerability was reported allowing a specifically-configured
MySQL server to execute an XSS attack. This particular attack requires
configuring the MySQL server log_bin directive with the payload.

- Several XSS vulnerabilities were found with the Transformation
feature

- Several XSS vulnerabilities were found in AJAX error handling

- Several XSS vulnerabilities were found in the Designer feature

- An XSS vulnerability was found in the charts feature

- An XSS vulnerability was found in the zoom search feature Severity
We consider these attacks to be of moderate severity. Summary Unsafe
handling of preg_replace parameters Description In some versions of
PHP, it's possible for an attacker to pass parameters to the
preg_replace() function which can allow the execution of arbitrary PHP
code. This code is not properly sanitized in phpMyAdmin as part of the
table search and replace feature. Severity We consider this
vulnerability to be of moderate severity. Summary Referrer leak in
transformations Description A vulnerability was reported where a
specially crafted Transformation could be used to leak information
including the authentication token. This could be used to direct a
CSRF attack against a user.

Furthermore, the CSP code used in version 4.0.x is outdated and has
been updated to more modern standards. Severity We consider this to be
of moderate severity"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-17/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-18/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-19/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-20/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-21/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-22/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-24/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-25/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-27/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-28/"
  );
  # http://www.freebsd.org/ports/portaudit/e7028e1d-3f9b-11e6-81f9-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5a1f642"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
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

if (pkg_test(save_report:TRUE, pkg:"phpmyadmin>=4.6.0<4.6.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
