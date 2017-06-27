#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201610-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(93992);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/12 13:47:11 $");

  script_cve_id("CVE-2014-0032", "CVE-2014-3504", "CVE-2014-3522", "CVE-2014-3528", "CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187", "CVE-2015-5259", "CVE-2016-2167", "CVE-2016-2168");
  script_xref(name:"GLSA", value:"201610-05");

  script_name(english:"GLSA-201610-05 : Subversion, Serf: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201610-05
(Subversion, Serf: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in Subversion and Serf.
      Please review the CVE identifiers referenced below for details
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, conduct a man-in-the-middle attack, obtain
      sensitive information, or cause a Denial of Service Condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201610-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Subversion users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-vcs/subversion-1.9.4'
    All Serf users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/serf-1.3.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:serf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-vcs/subversion", unaffected:make_list("ge 1.9.4", "rgt 1.8.16"), vulnerable:make_list("lt 1.9.4"))) flag++;
if (qpkg_check(package:"net-libs/serf", unaffected:make_list("ge 1.3.7"), vulnerable:make_list("lt 1.3.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subversion / Serf");
}
