#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15429);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_osvdb_id(10005);
  script_xref(name:"GLSA", value:"200410-04");

  script_name(english:"GLSA-200410-04 : PHP: Memory disclosure and arbitrary location file upload");
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
"The remote host is affected by the vulnerability described in GLSA-200410-04
(PHP: Memory disclosure and arbitrary location file upload)

    Stefano Di Paola discovered two bugs in PHP. The first is a parse error in
    php_variables.c that could allow a remote attacker to view the contents of
    the target machine's memory. Additionally, an array processing error in the
    SAPI_POST_HANDLER_FUNC() function inside rfc1867.c could lead to the
    $_FILES array being overwritten.
  
Impact :

    A remote attacker could exploit the first vulnerability to view memory
    contents. On a server with a script that provides file uploads, an attacker
    could exploit the second vulnerability to upload files to an arbitrary
    location. On systems where the HTTP server is allowed to write in a
    HTTP-accessible location, this could lead to remote execution of arbitrary
    commands with the rights of the HTTP server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/12560/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/375294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/375370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv '>=dev-php/php-4.3.9'
    # emerge '>=dev-php/php-4.3.9'
    # emerge -pv '>=dev-php/mod_php-4.3.9'
    # emerge '>=dev-php/mod_php-4.3.9'
    # emerge -pv '>=dev-php/php-cgi-4.3.9'
    # emerge '>=dev-php/php-cgi-4.3.9'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-php/php-cgi", unaffected:make_list("ge 4.3.9"), vulnerable:make_list("lt 4.3.9"))) flag++;
if (qpkg_check(package:"dev-php/php", unaffected:make_list("ge 4.3.9 "), vulnerable:make_list("lt 4.3.9"))) flag++;
if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("ge 4.3.9"), vulnerable:make_list("lt 4.3.9"))) flag++;

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
