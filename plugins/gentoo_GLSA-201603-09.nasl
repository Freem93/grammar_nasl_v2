#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-09.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(89902);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/10 14:25:16 $");

  script_cve_id("CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1275", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289", "CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1295", "CVE-2015-1296", "CVE-2015-1297", "CVE-2015-1298", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1302", "CVE-2015-1303", "CVE-2015-1304", "CVE-2015-6755", "CVE-2015-6756", "CVE-2015-6757", "CVE-2015-6758", "CVE-2015-6759", "CVE-2015-6760", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763", "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6783", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791", "CVE-2015-6792", "CVE-2015-8126", "CVE-2016-1612", "CVE-2016-1613", "CVE-2016-1614", "CVE-2016-1615", "CVE-2016-1616", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1619", "CVE-2016-1620", "CVE-2016-1621", "CVE-2016-1622", "CVE-2016-1623", "CVE-2016-1624", "CVE-2016-1625", "CVE-2016-1626", "CVE-2016-1627", "CVE-2016-1628", "CVE-2016-1629", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641");
  script_xref(name:"GLSA", value:"201603-09");

  script_name(english:"GLSA-201603-09 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201603-09
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the Chromium web
      browser. Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, obtain
      sensitive information, or bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-49.0.2623.87'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 49.0.2623.87"), vulnerable:make_list("lt 49.0.2623.87"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
