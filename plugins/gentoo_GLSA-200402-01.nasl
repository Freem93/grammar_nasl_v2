#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200402-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14445);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200402-01");

  script_name(english:"GLSA-200402-01 : PHP setting leaks from .htaccess files on virtual hosts");
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
"The remote host is affected by the vulnerability described in GLSA-200402-01
(PHP setting leaks from .htaccess files on virtual hosts)

    If the server configuration 'php.ini' file has
    'register_globals = on' and a request is made to one virtual host
    (which has 'php_admin_flag register_globals off') and the next
    request is sent to the another virtual host (which does not have the
    setting) through the same apache child, the setting will persist.
  
Impact :

    Depending on the server and site, an attacker may be able to exploit
    global variables to gain access to reserved areas, such as MySQL passwords,
    or this vulnerability may simply cause a lack of functionality. As a
    result, users are urged to upgrade their PHP installations.
    Gentoo ships PHP with 'register_globals' set to 'off'
    by default.
    This issue affects both servers running Apache 1.x and servers running
    Apache 2.x.
  
Workaround :

    No immediate workaround is available; a software upgrade is required."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.php.net/bug.php?id=25753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200402-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are recommended to upgrade their PHP installation to 4.3.4-r4:
    # emerge sync
    # emerge -pv '>=dev-php/mod_php-4.3.4-r4'
    # emerge '>=dev-php/mod_php-4.3.4-r4'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("ge 4.3.4-r4"), vulnerable:make_list("lt 4.3.4-r4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-php/mod_php");
}
