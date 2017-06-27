#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201610-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(93993);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/12 13:47:11 $");

  script_cve_id("CVE-2015-2582", "CVE-2015-2611", "CVE-2015-2617", "CVE-2015-2620", "CVE-2015-2639", "CVE-2015-2641", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-2661", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4756", "CVE-2015-4757", "CVE-2015-4767", "CVE-2015-4769", "CVE-2015-4771", "CVE-2015-4772");
  script_xref(name:"GLSA", value:"201610-06");

  script_name(english:"GLSA-201610-06 : MySQL and MariaDB: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201610-06
(MySQL and MariaDB: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL and MariaDB.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could exploit vulnerabilities, through multiple
      vectors, that affect the confidentiality, integrity, and availability of
      MySQL and MariaDB.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201610-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.6.31'
    All MariaDB users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mariadb-10.0.27'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mariab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
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

if (qpkg_check(package:"dev-db/mariadb", unaffected:make_list("rgt 5.5.51"), vulnerable:make_list("lt 10.0.27"))) flag++;
if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.6.31"), vulnerable:make_list("lt 5.6.31"))) flag++;
if (qpkg_check(package:"dev-db/mariab", unaffected:make_list("ge 10.0.27"), vulnerable:make_list())) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL and MariaDB");
}
