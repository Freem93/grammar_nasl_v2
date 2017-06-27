#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14477);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"GLSA", value:"200404-12");

  script_name(english:"GLSA-200404-12 : Scorched 3D server chat box format string vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200404-12
(Scorched 3D server chat box format string vulnerability)

    Scorched 3D (build 36.2 and before) does not properly check the text
    entered in the Chat box (T key). Using format string characters, you can
    generate a heap overflow. This and several other unchecked buffers have
    been corrected in the build 37 release.
  
Impact :

    This vulnerability can be easily exploited to remotely crash the Scorched
    3D server, disconnecting all clients. It could also theoretically be used to
    execute arbitrary code on the server with the rights of the user running
    the server.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Scorched 3D users should upgrade to version 37 or later:
    # emerge sync
    # emerge -pv '>=games-strategy/scorched3d-37'
    # emerge '>=games-strategy/scorched3d-37'"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:scorched3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/09");
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

if (qpkg_check(package:"games-strategy/scorched3d", unaffected:make_list("ge 37"), vulnerable:make_list("lt 37"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "games-strategy/scorched3d");
}
