#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18170);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_osvdb_id(15762, 15763, 15764, 15765, 15766, 15767, 15768, 15769, 15782, 15797);
  script_xref(name:"GLSA", value:"200505-01");

  script_name(english:"GLSA-200505-01 : Horde Framework: Multiple XSS vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200505-01
(Horde Framework: Multiple XSS vulnerabilities)

    Cross-site scripting vulnerabilities have been discovered in
    various modules of the Horde Framework.
  
Impact :

    These vulnerabilities could be exploited by an attacker to execute
    arbitrary HTML and script code in context of the victim's browser.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://marc.theaimsgroup.com/?l=horde-announce&r=1&b=200504&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=horde-announce&r=1&b=200504&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-2.2.8'
    All Horde Vacation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-vacation-2.2.2'
    All Horde Turba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-turba-1.2.5'
    All Horde Passwd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-passwd-2.2.2'
    All Horde Nag users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-nag-1.1.3'
    All Horde Mnemo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-mnemo-1.1.4'
    All Horde Kronolith users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-kronolith-1.1.4'
    All Horde IMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-imp-3.2.8'
    All Horde Accounts users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-accounts-2.1.2'
    All Horde Forwards users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-forwards-2.2.2'
    All Horde Chora users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-chora-1.2.3'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-chora");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-forwards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-imp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-kronolith");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-mnemo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-nag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-turba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-vacation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/horde-vacation", unaffected:make_list("ge 2.2.2"), vulnerable:make_list("lt 2.2.2"))) flag++;
if (qpkg_check(package:"www-apps/horde", unaffected:make_list("ge 2.2.8"), vulnerable:make_list("lt 2.2.8"))) flag++;
if (qpkg_check(package:"www-apps/horde-kronolith", unaffected:make_list("ge 1.1.4"), vulnerable:make_list("lt 1.1.4"))) flag++;
if (qpkg_check(package:"www-apps/horde-imp", unaffected:make_list("ge 3.2.8"), vulnerable:make_list("lt 3.2.8"))) flag++;
if (qpkg_check(package:"www-apps/horde-nag", unaffected:make_list("ge 1.1.3"), vulnerable:make_list("lt 1.1.3"))) flag++;
if (qpkg_check(package:"www-apps/horde-accounts", unaffected:make_list("ge 2.1.2"), vulnerable:make_list("lt 2.1.2"))) flag++;
if (qpkg_check(package:"www-apps/horde-chora", unaffected:make_list("ge 1.2.3"), vulnerable:make_list("lt 1.2.3"))) flag++;
if (qpkg_check(package:"www-apps/horde-forwards", unaffected:make_list("ge 2.2.2"), vulnerable:make_list("lt 2.2.2"))) flag++;
if (qpkg_check(package:"www-apps/horde-passwd", unaffected:make_list("ge 2.2.2"), vulnerable:make_list("lt 2.2.2"))) flag++;
if (qpkg_check(package:"www-apps/horde-mnemo", unaffected:make_list("ge 1.1.4"), vulnerable:make_list("lt 1.1.4"))) flag++;
if (qpkg_check(package:"www-apps/horde-turba", unaffected:make_list("ge 1.2.5"), vulnerable:make_list("lt 1.2.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Horde Framework");
}
