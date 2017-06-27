#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200708-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25866);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");
  script_osvdb_id(34140, 38049, 38054);
  script_xref(name:"GLSA", value:"200708-01");

  script_name(english:"GLSA-200708-01 : Macromedia Flash Player: Remote arbitrary code execution");
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
"The remote host is affected by the vulnerability described in GLSA-200708-01
(Macromedia Flash Player: Remote arbitrary code execution)

    Mark Hills discovered some errors when interacting with a browser for
    keystrokes handling (CVE-2007-2022). Stefano Di Paola and Giorgio Fedon
    from Minded Security discovered a boundary error when processing FLV
    files (CVE-2007-3456). An input validation error when processing HTTP
    referrers has also been reported (CVE-2007-3457).
  
Impact :

    A remote attacker could entice a user to open a specially crafted file,
    possibly leading to the execution of arbitrary code with the privileges
    of the user running the Macromedia Flash Player, or sensitive data
    access.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200708-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Macromedia Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-9.0.48.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 9.0.48.0"), vulnerable:make_list("lt 9.0.48.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Macromedia Flash Player");
}
