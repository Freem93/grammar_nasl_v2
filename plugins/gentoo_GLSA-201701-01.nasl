#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201701-01.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(96232);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2016-3492", "CVE-2016-3495", "CVE-2016-5507", "CVE-2016-5584", "CVE-2016-5609", "CVE-2016-5612", "CVE-2016-5625", "CVE-2016-5626", "CVE-2016-5627", "CVE-2016-5628", "CVE-2016-5629", "CVE-2016-5630", "CVE-2016-5631", "CVE-2016-5632", "CVE-2016-5633", "CVE-2016-5634", "CVE-2016-5635", "CVE-2016-6652", "CVE-2016-6662", "CVE-2016-8283", "CVE-2016-8284", "CVE-2016-8286", "CVE-2016-8287", "CVE-2016-8288", "CVE-2016-8289", "CVE-2016-8290");
  script_xref(name:"GLSA", value:"201701-01");

  script_name(english:"GLSA-201701-01 : MariaDB and MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201701-01
(MariaDB and MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MariaDB and MySQL.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    Attackers could execute arbitrary code, escalate privileges, and impact
      availability via unspecified vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201701-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MariaDB users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mariadb-10.0.28'
    All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.6.34'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/mariadb", unaffected:make_list("ge 10.0.28"), vulnerable:make_list("lt 10.0.28"))) flag++;
if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.6.34"), vulnerable:make_list("lt 5.6.34"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MariaDB and MySQL");
}
