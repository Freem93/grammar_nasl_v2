#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-19.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32012);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-1734");
  script_osvdb_id(44728);
  script_xref(name:"GLSA", value:"200804-19");

  script_name(english:"GLSA-200804-19 : PHP Toolkit: Data disclosure and Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200804-19
(PHP Toolkit: Data disclosure and Denial of Service)

    Toni Arnold, David Sveningsson, Michal Bartoszkiewicz, and Joseph
    reported that php-select does not quote parameters passed to the 'tr'
    command, which could convert the '-D PHP5' argument in the
    'APACHE2_OPTS' setting in the file /etc/conf.d/apache2 to lower case.
  
Impact :

    An attacker could entice a system administrator to run 'emerge
    php' or call 'php-select -t apache2 php5' directly in a
    directory containing a lower case single-character named file, which
    would prevent Apache from loading mod_php and thereby disclose PHP
    source code and cause a Denial of Service.
  
Workaround :

    Do not run 'emerge' or 'php-select' from a working directory which
    contains a lower case single-character named file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP Toolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/php-toolkit-1.0.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-toolkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/php-toolkit", unaffected:make_list("ge 1.0.1"), vulnerable:make_list("lt 1.0.1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP Toolkit");
}
