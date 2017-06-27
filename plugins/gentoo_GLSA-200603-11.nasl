#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200603-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21084);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2006-0047");
  script_osvdb_id(23667);
  script_xref(name:"GLSA", value:"200603-11");

  script_name(english:"GLSA-200603-11 : Freeciv: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200603-11
(Freeciv: Denial of Service)

    Luigi Auriemma discovered that Freeciv could be tricked into the
    allocation of enormous chunks of memory when trying to uncompress
    malformed data packages, possibly leading to an out of memory condition
    which causes Freeciv to crash or freeze.
  
Impact :

    A remote attacker could exploit this issue to cause a Denial of
    Service by sending specially crafted data packages to the Freeciv game
    server.
  
Workaround :

    Play solo games or restrict your multiplayer games to trusted
    parties."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aluigi.altervista.org/adv/freecivdos-adv.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200603-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Freeciv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-strategy/freeciv-2.0.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:freeciv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"games-strategy/freeciv", unaffected:make_list("ge 2.0.8"), vulnerable:make_list("lt 2.0.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Freeciv");
}
