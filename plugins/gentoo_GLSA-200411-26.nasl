#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-26.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15754);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-1115", "CVE-2004-1116", "CVE-2004-1117");
  script_osvdb_id(11923, 11924, 11925);
  script_xref(name:"GLSA", value:"200411-26");

  script_name(english:"GLSA-200411-26 : GIMPS, SETI@home, ChessBrain: Insecure installation");
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
"The remote host is affected by the vulnerability described in GLSA-200411-26
(GIMPS, SETI@home, ChessBrain: Insecure installation)

    GIMPS, SETI@home and ChessBrain ebuilds install user-owned binaries and
    init scripts which are executed with root privileges.
  
Impact :

    This could lead to a local privilege escalation or root compromise.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GIMPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sci-misc/gimps-23.9-r1'
    All SETI@home users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sci-misc/setiathome-3.03-r2'
    All ChessBrain users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sci-misc/chessbrain-20407-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chessbrain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gimps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:setiathome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/17");
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

if (qpkg_check(package:"sci-misc/setiathome", unaffected:make_list("ge 3.08-r4", "rge 3.03-r2"), vulnerable:make_list("le 3.08-r3"))) flag++;
if (qpkg_check(package:"sci-misc/gimps", unaffected:make_list("ge 23.9-r1"), vulnerable:make_list("le 23.9"))) flag++;
if (qpkg_check(package:"sci-misc/chessbrain", unaffected:make_list("ge 20407-r1"), vulnerable:make_list("le 20407"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GIMPS / SETI@home / ChessBrain");
}
