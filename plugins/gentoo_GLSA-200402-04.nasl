#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200402-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14448);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200402-04");

  script_name(english:"GLSA-200402-04 : Gallery 1.4.1 and below remote exploit vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200402-04
(Gallery 1.4.1 and below remote exploit vulnerability)

    Starting in the 1.3.1 release, Gallery includes code to simulate the behaviour
    of the PHP 'register_globals' variable in environments where that setting
    is disabled.  It is simulated by extracting the values of the various
    $HTTP_ global variables into the global namespace.
  
Impact :

    A crafted URL such as
    http://example.com/gallery/init.php?HTTP_POST_VARS=xxx  causes the
    'register_globals' simulation code to overwrite the $HTTP_POST_VARS which,
    when it is extracted, will deliver the given payload. If the
    payload compromises $GALLERY_BASEDIR then the malicious user can perform a
    PHP injection exploit and gain remote access to the webserver with PHP
    user UID access rights.
  
Workaround :

    The workaround for the vulnerability is to replace init.php and
    setup/init.php with the files in the following ZIP file:
    http://prdownloads.sourceforge.net/gallery/patch_1.4.1-to-1.4.1-pl1.zip?download"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200402-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are encouraged to upgrade their gallery installation:
    # emerge sync
    # emerge -p '>=www-apps/gallery-1.4.1_p1'
    # emerge '>=www-apps/gallery-1.4.1_p1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gallery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/11");
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

if (qpkg_check(package:"www-apps/gallery", unaffected:make_list("ge 1.4.1_p1"), vulnerable:make_list("lt 1.4.1_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "www-apps/gallery");
}
