#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14546);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_osvdb_id(7870, 7871);
  script_xref(name:"GLSA", value:"200407-13");

  script_name(english:"GLSA-200407-13 : PHP: Multiple security vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200407-13
(PHP: Multiple security vulnerabilities)

    Several security vulnerabilities were found and fixed in version 4.3.8 of
    PHP. The strip_tags() function, used to sanitize user input, could in
    certain cases allow tags containing \\0 characters (CAN-2004-0595). When
    memory_limit is used, PHP might unsafely interrupt other functions
    (CAN-2004-0594). The ftok and itpc functions were missing safe_mode checks.
    It was possible to bypass open_basedir restrictions using MySQL's LOAD DATA
    LOCAL function. Furthermore, the IMAP extension was incorrectly allocating
    memory and alloca() calls were replaced with emalloc() for better stack
    protection.
  
Impact :

    Successfully exploited, the memory_limit problem could allow remote
    execution of arbitrary code. By exploiting the strip_tags vulnerability, it
    is possible to pass HTML code that would be considered as valid tags by the
    Microsoft Internet Explorer and Safari browsers. Using ftok, itpc or
    MySQL's LOAD DATA LOCAL, it is possible to bypass PHP configuration
    restrictions.
  
Workaround :

    There is no known workaround that would solve all these problems. All users
    are encouraged to upgrade to the latest available versions."
  );
  # http://security.e-matters.de/advisories/112004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83c215d0"
  );
  # http://security.e-matters.de/advisories/122004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4bce03"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv '>=dev-php/php-4.3.8'
    # emerge '>=dev-php/php-4.3.8'
    # emerge -pv '>=dev-php/mod_php-4.3.8'
    # emerge '>=dev-php/mod_php-4.3.8'
    # emerge -pv '>=dev-php/php-cgi-4.3.8'
    # emerge '>=dev-php/php-cgi-4.3.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-php/php-cgi", unaffected:make_list("ge 4.3.8"), vulnerable:make_list("le 4.3.7-r1"))) flag++;
if (qpkg_check(package:"dev-php/php", unaffected:make_list("ge 4.3.8"), vulnerable:make_list("le 4.3.7-r1"))) flag++;
if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("ge 4.3.8"), vulnerable:make_list("le 4.3.7-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
