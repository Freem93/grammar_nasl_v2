#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200402-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14449);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/03/14 14:55:46 $");

  script_xref(name:"GLSA", value:"200402-05");

  script_name(english:"GLSA-200402-05 : phpMyAdmin < 2.5.6-rc1: possible attack against export.php");
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
"The remote host is affected by the vulnerability described in GLSA-200402-05
(phpMyAdmin < 2.5.6-rc1: possible attack against export.php)

    One component of the phpMyAdmin software package (export.php) does not
    properly verify input that is passed to it from a remote user.  Since the
    input is used to include other files, it is possible to launch a directory
    traversal attack.
  
Impact :

    Private information could be gleaned from the remote server if an attacker
    uses a malformed URL such as http://phpmyadmin.example.com/export.php?what=../../../[existing_file]
    In this scenario, the script does not sanitize the 'what' argument passed
    to it, allowing directory traversal attacks to take place, disclosing
    the contents of files if the file is readable as the web-server user.
  
Workaround :

    The workaround is to either patch the export.php file using the
    referenced CVS patch or upgrade the software via Portage."
  );
  # http://cvs.sourceforge.net/viewcvs.py/phpmyadmin/phpMyAdmin/export.php?r1=2.3&r2=2.3.2.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?848f6be3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200402-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to phpMyAdmin-2.5.6_rc1:
    # emerge sync
    # emerge -pv '>=dev-db/phpmyadmin-2.5.6_rc1'
    # emerge '>=dev-db/phpmyadmin-2.5.6_rc1'
    # emerge clean"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 2.5.6_rc1"), vulnerable:make_list("le 2.5.5_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin < 2.5.6-rc1");
}
