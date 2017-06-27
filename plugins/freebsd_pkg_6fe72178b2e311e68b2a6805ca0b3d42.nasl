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
  script_id(95364);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-4412", "CVE-2016-6632", "CVE-2016-6633");

  script_name(english:"FreeBSD : phpMyAdmin -- multiple vulnerabilities (6fe72178-b2e3-11e6-8b2a-6805ca0b3d42)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The phpMYAdmin development team reports : Summary Open redirection
Description A vulnerability was discovered where a user can be tricked
in to following a link leading to phpMyAdmin, which after
authentication redirects to another malicious site.

The attacker must sniff the user's valid phpMyAdmin token. Severity We
consider this vulnerability to be of moderate severity. Summary Unsafe
generation of blowfish secret Description When the user does not
specify a blowfish_secret key for encrypting cookies, phpMyAdmin
generates one at runtime. A vulnerability was reported where the way
this value is created using a weak algorithm.

This could allow an attacker to determine the user's blowfish_secret
and potentially decrypt their cookies. Severity We consider this
vulnerability to be of moderate severity. Mitigation factor This
vulnerability only affects cookie authentication and only when a user
has not defined a $cfg['blowfish_secret'] in their config.inc.php
Summary phpinfo information leak value of sensitive (HttpOnly) cookies
Description phpinfo (phpinfo.php) shows PHP information including
values of HttpOnly cookies. Severity We consider this vulnerability to
be non-critical. Mitigation factor phpinfo in disabled by default and
needs to be enabled explicitly. Summary Username deny rules bypass
(AllowRoot & Others) by using Null Byte Description It is possible to
bypass AllowRoot restriction ($cfg['Servers'][$i]['AllowRoot']) and
deny rules for username by using Null Byte in the username. Severity
We consider this vulnerability to be severe. Summary Username rule
matching issues Description A vulnerability in username matching for
the allow/deny rules may result in wrong matches and detection of the
username in the rule due to non-constant execution time. Severity We
consider this vulnerability to be severe. Summary Bypass logout
timeout Description With a crafted request parameter value it is
possible to bypass the logout timeout. Severity We consider this
vulnerability to be of moderate severity. Summary Multiple full path
disclosure vulnerabilities Description By calling some scripts that
are part of phpMyAdmin in an unexpected way, it is possible to trigger
phpMyAdmin to display a PHP error message which contains the full path
of the directory where phpMyAdmin is installed. During an execution
timeout in the export functionality, the errors containing the full
path of the directory of phpMyAdmin is written to the export file.
Severity We consider these vulnerability to be non-critical. Summary
Multiple XSS vulnerabilities Description Several XSS vulnerabilities
have been reported, including an improper fix for PMASA-2016-10 and a
weakness in a regular expression using in some JavaScript processing.
Severity We consider this vulnerability to be non-critical. Summary
Multiple DOS vulnerabilities Description With a crafted request
parameter value it is possible to initiate a denial of service attack
in saved searches feature.

With a crafted request parameter value it is possible to initiate a
denial of service attack in import feature.

An unauthenticated user can execute a denial of service attack when
phpMyAdmin is running with $cfg['AllowArbitraryServer']=true;.
Severity We consider these vulnerabilities to be of moderate severity.
Summary Bypass white-list protection for URL redirection Description
Due to the limitation in URL matching, it was possible to bypass the
URL white-list protection. Severity We consider this vulnerability to
be of moderate severity. Summary BBCode injection vulnerability
Description With a crafted login request it is possible to inject
BBCode in the login page. Severity We consider this vulnerability to
be severe. Mitigation factor This exploit requires phpMyAdmin to be
configured with the 'cookie' auth_type; other authentication methods
are not affected. Summary DOS vulnerability in table partitioning
Description With a very large request to table partitioning function,
it is possible to invoke a Denial of Service (DOS) attack. Severity We
consider this vulnerability to be of moderate severity. Summary
Multiple SQL injection vulnerabilities Description With a crafted
username or a table name, it was possible to inject SQL statements in
the tracking functionality that would run with the privileges of the
control user. This gives read and write access to the tables of the
configuration storage database, and if the control user has the
necessary privileges, read access to some tables of the mysql
database. Severity We consider these vulnerabilities to be serious.
Summary Incorrect serialized string parsing Description Due to a bug
in serialized string parsing, it was possible to bypass the protection
offered by PMA_safeUnserialize() function. Severity We consider this
vulnerability to be severe. Summary CSRF token not stripped from the
URL Description When the arg_separator is different from its default
value of &, the token was not properly stripped from the return URL of
the preference import action. Severity We have not yet determined a
severity for this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-57/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-58/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-59/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-60/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-61/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-62/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-63/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-64/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-65/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-66/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-67/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-68/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-69/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-70/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-71/"
  );
  # http://www.freebsd.org/ports/portaudit/6fe72178-b2e3-11e6-8b2a-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdd9b855"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
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

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin>=4.6.0<4.6.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
