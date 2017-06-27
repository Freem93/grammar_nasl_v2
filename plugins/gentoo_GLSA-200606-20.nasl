#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200606-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21732);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-1515");
  script_osvdb_id(25941);
  script_xref(name:"GLSA", value:"200606-20");

  script_name(english:"GLSA-200606-20 : Typespeed: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200606-20
(Typespeed: Remote execution of arbitrary code)

    Niko Tyni discovered a buffer overflow in the addnewword() function of
    Typespeed's network code.
  
Impact :

    By sending specially crafted network packets to a machine running
    Typespeed in multiplayer mode, a remote attacker can execute arbitrary
    code with the permissions of the user running the game.
  
Workaround :

    Do not run Typespeed in multiplayer mode. There is no known workaround
    at this time for multiplayer mode."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200606-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Typespeed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-misc/typespeed-0.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:typespeed");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/31");
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

if (qpkg_check(package:"games-misc/typespeed", unaffected:make_list("ge 0.5.0"), vulnerable:make_list("lt 0.5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Typespeed");
}