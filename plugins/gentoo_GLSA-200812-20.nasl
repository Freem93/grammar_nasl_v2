#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35257);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2006-1495", "CVE-2008-4303", "CVE-2008-4304", "CVE-2008-4305");
  script_osvdb_id(24226, 24227, 24230, 50948, 50949, 53103);
  script_xref(name:"GLSA", value:"200812-20");

  script_name(english:"GLSA-200812-20 : phpCollab: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200812-20
(phpCollab: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in phpCollab:
    rgod reported that data sent to general/sendpassword.php via the
    loginForm parameter is not properly sanitized before being used in an
    SQL statement (CVE-2006-1495).
    Christian Hoffmann of Gentoo
    Security discovered multiple vulnerabilities where input is
    insufficiently sanitized before being used in a SQL statement, for
    instance in general/login.php via the loginForm parameter.
    (CVE-2008-4303).
    Christian Hoffmann also found out that the
    variable $SSL_CLIENT_CERT in general/login.php is not properly
    sanitized before being used in a shell command. (CVE-2008-4304).
    User-supplied data to installation/setup.php is not checked before
    being written to include/settings.php which is executed later. This
    issue was reported by Christian Hoffmann as well (CVE-2008-4305).
  
Impact :

    These vulnerabilities enable remote attackers to execute arbitrary SQL
    statements and PHP code. NOTE: Some of the SQL injection
    vulnerabilities require the php.ini option 'magic_quotes_gpc' to be
    disabled. Furthermore, an attacker might be able to execute arbitrary
    shell commands if 'register_globals' is enabled, 'magic_quotes_gpc' is
    disabled, the PHP OpenSSL extension is not installed or loaded and the
    file 'installation/setup.php' has not been deleted after installation.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"phpCollab has been removed from the Portage tree. We recommend that
    users unmerge phpCollab:
    # emerge --unmerge 'www-apps/phpcollab'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(78, 89, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpcollab");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/phpcollab", unaffected:make_list(), vulnerable:make_list("le 2.5_rc3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpCollab");
}
