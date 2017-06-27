#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201409-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77548);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2013-1861", "CVE-2013-2134", "CVE-2013-3839", "CVE-2013-5767", "CVE-2013-5770", "CVE-2013-5786", "CVE-2013-5793", "CVE-2013-5807", "CVE-2013-5860", "CVE-2013-5881", "CVE-2013-5882", "CVE-2013-5891", "CVE-2013-5894", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0384", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0427", "CVE-2014-0430", "CVE-2014-0431", "CVE-2014-0433", "CVE-2014-0437", "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2432", "CVE-2014-2434", "CVE-2014-2435", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2440");
  script_bugtraq_id(58511, 60346, 63105, 63107, 63109, 63113, 63116, 63119, 64849, 64854, 64864, 64868, 64873, 64877, 64880, 64885, 64888, 64891, 64893, 64895, 64896, 64897, 64898, 64904, 64908, 65298, 66835, 66846, 66850, 66853, 66858, 66872, 66875, 66880, 66890, 66896);
  script_osvdb_id(98509, 102070, 102077, 102078, 102713, 105910, 105911, 105912, 105914, 105915, 105916, 105917);
  script_xref(name:"GLSA", value:"201409-04");

  script_name(english:"GLSA-201409-04 : MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201409-04
(MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A local attacker could possibly gain escalated privileges. A remote
      attacker could send a specially crafted SQL query, possibly resulting in
      a Denial of Service condition. A remote attacker could entice a user to
      connect to specially crafted MySQL server, possibly resulting in
      execution of arbitrary code with the privileges of the process.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201409-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.5.39'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.5.39"), vulnerable:make_list("lt 5.5.39"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
