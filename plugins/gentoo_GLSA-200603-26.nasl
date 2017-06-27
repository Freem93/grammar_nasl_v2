#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200603-26.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21166);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2006-1539");
  script_osvdb_id(24261);
  script_xref(name:"GLSA", value:"200603-26");

  script_name(english:"GLSA-200603-26 : bsd-games: Local privilege escalation in tetris-bsd");
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
"The remote host is affected by the vulnerability described in GLSA-200603-26
(bsd-games: Local privilege escalation in tetris-bsd)

    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered that
    the checkscores() function in scores.c reads in the data from the
    /var/games/tetris-bsd.scores file without validation, rendering it
    vulnerable to buffer overflows and incompatible with the system used
    for managing games on Gentoo Linux. As a result, it cannot be played
    securely on systems with multiple users. Please note that this is
    probably a Gentoo-specific issue.
  
Impact :

    A local user who is a member of group 'games' may be able to modify the
    tetris-bsd.scores file to trigger the execution of arbitrary code with
    the privileges of other players.
  
Workaround :

    Do not add untrusted users to the 'games' group."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200603-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All bsd-games users are advised to update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-misc/bsd-games-2.17-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bsd-games");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/29");
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

if (qpkg_check(package:"games-misc/bsd-games", unaffected:make_list("ge 2.17-r1"), vulnerable:make_list("lt 2.17-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsd-games");
}
