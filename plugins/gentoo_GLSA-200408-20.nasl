#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14576);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_osvdb_id(9026, 9035, 9036);
  script_xref(name:"GLSA", value:"200408-20");

  script_name(english:"GLSA-200408-20 : Qt: Image loader overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200408-20
(Qt: Image loader overflows)

    There are several unspecified bugs in the QImage class which may cause
    crashes or allow execution of arbitrary code as the user running the Qt
    application. These bugs affect the PNG, XPM, BMP, GIF and JPEG image
    types.
  
Impact :

    An attacker may exploit these bugs by causing a user to open a
    carefully-constructed image file in any one of these formats. This may
    be accomplished through e-mail attachments (if the user uses KMail), or
    by simply placing a malformed image on a website and then convicing the
    user to load the site in a Qt-based browser (such as Konqueror).
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Qt."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:085"
  );
  # http://www.trolltech.com/developer/changes/changes-3.3.3.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9aaee330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Qt users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=x11-libs/qt-3.3.3'
    # emerge '>=x11-libs/qt-3.3.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
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

if (qpkg_check(package:"x11-libs/qt", unaffected:make_list("ge 3.3.3"), vulnerable:make_list("le 3.3.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Qt");
}
