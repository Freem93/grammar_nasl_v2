#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15725);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_osvdb_id(11595);
  script_xref(name:"GLSA", value:"200411-24");

  script_name(english:"GLSA-200411-24 : BNC: Buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200411-24
(BNC: Buffer overflow vulnerability)

    Leon Juranic discovered that BNC fails to do proper bounds
    checking when checking server response.
  
Impact :

    An attacker could exploit this to cause a Denial of Service and
    potentially execute arbitary code with the permissions of the user
    running BNC.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://gotbnc.com/changes.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e9d3c1f"
  );
  # http://security.lss.hr/en/index.php?page=details&ID=LSS-2004-11-03
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?388d13fb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-irc/bnc-2.9.1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
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

if (qpkg_check(package:"net-irc/bnc", unaffected:make_list("ge 2.9.1"), vulnerable:make_list("lt 2.9.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BNC");
}
