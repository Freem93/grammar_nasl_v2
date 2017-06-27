#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32151);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-1142", "CVE-2008-1692");
  script_osvdb_id(43902, 43903, 45081, 45082, 45083, 45084);
  script_xref(name:"GLSA", value:"200805-03");

  script_name(english:"GLSA-200805-03 : Multiple X11 terminals: Local privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200805-03
(Multiple X11 terminals: Local privilege escalation)

    Bernhard R. Link discovered that RXVT opens a terminal on :0 if the
    '-display' option is not specified and the DISPLAY environment variable
    is not set. Further research by the Gentoo Security Team has shown that
    aterm, Eterm, Mrxvt, multi-aterm, rxvt-unicode, and wterm are also
    affected.
  
Impact :

    A local attacker could exploit this vulnerability to hijack X11
    terminals of other users.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200805-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All aterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/aterm-1.0.1-r1'
    All Eterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/eterm-0.9.4-r1'
    All Mrxvt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/mrxvt-0.5.3-r2'
    All multi-aterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/multi-aterm-0.2.1-r1'
    All RXVT users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-2.7.10-r4'
    All rxvt-unicode users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-unicode-9.02-r1'
    All wterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/wterm-6.2.9-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:eterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mrxvt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:multi-aterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rxvt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rxvt-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wterm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
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

if (qpkg_check(package:"x11-terms/aterm", unaffected:make_list("ge 1.0.1-r1"), vulnerable:make_list("lt 1.0.1-r1"))) flag++;
if (qpkg_check(package:"x11-terms/rxvt", unaffected:make_list("ge 2.7.10-r4"), vulnerable:make_list("lt 2.7.10-r4"))) flag++;
if (qpkg_check(package:"x11-terms/multi-aterm", unaffected:make_list("ge 0.2.1-r1"), vulnerable:make_list("lt 0.2.1-r1"))) flag++;
if (qpkg_check(package:"x11-terms/wterm", unaffected:make_list("ge 6.2.9-r3"), vulnerable:make_list("lt 6.2.9-r3"))) flag++;
if (qpkg_check(package:"x11-terms/mrxvt", unaffected:make_list("ge 0.5.3-r2"), vulnerable:make_list("lt 0.5.3-r2"))) flag++;
if (qpkg_check(package:"x11-terms/eterm", unaffected:make_list("ge 0.9.4-r1"), vulnerable:make_list("lt 0.9.4-r1"))) flag++;
if (qpkg_check(package:"x11-terms/rxvt-unicode", unaffected:make_list("ge 9.02-r1"), vulnerable:make_list("lt 9.02-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Multiple X11 terminals");
}
