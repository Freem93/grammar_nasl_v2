#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201504-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(82632);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2013-1741", "CVE-2013-2566", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607", "CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673", "CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1520", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532", "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1539", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542", "CVE-2014-1543", "CVE-2014-1544", "CVE-2014-1545", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1551", "CVE-2014-1552", "CVE-2014-1553", "CVE-2014-1554", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1561", "CVE-2014-1562", "CVE-2014-1563", "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1566", "CVE-2014-1567", "CVE-2014-1568", "CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1580", "CVE-2014-1581", "CVE-2014-1582", "CVE-2014-1583", "CVE-2014-1584", "CVE-2014-1585", "CVE-2014-1586", "CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594", "CVE-2014-5369", "CVE-2014-8631", "CVE-2014-8632", "CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642", "CVE-2015-0817", "CVE-2015-0818", "CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0828", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0833", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836");
  script_xref(name:"GLSA", value:"201504-01");

  script_name(english:"GLSA-201504-01 : Mozilla Products: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201504-01
(Mozilla Products: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Firefox, Thunderbird,
      and SeaMonkey. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page or email, possibly resulting in execution of arbitrary code or a
      Denial of Service condition. Furthermore, a remote attacker may be able
      to perform Man-in-the-Middle attacks, obtain sensitive information, spoof
      the address bar, conduct clickjacking attacks, bypass security
      restrictions and protection mechanisms,  or have other unspecified
      impact.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201504-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-31.5.3'
    All firefox-bin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-31.5.3'
    All thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-31.5.0'
    All thunderbird-bin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-31.5.0'
    All seamonkey users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-2.33.1'
    All seamonkey-bin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-2.33.1'
    All nspr users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/nspr-4.10.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox Proxy Prototype Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/nspr", unaffected:make_list("ge 4.10.6"), vulnerable:make_list("lt 4.10.6"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 2.33.1"), vulnerable:make_list("lt 2.33.1"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 31.5.0"), vulnerable:make_list("lt 31.5.0"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 31.5.0"), vulnerable:make_list("lt 31.5.0"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 31.5.3"), vulnerable:make_list("lt 31.5.3"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 2.33.1"), vulnerable:make_list("lt 2.33.1"))) flag++;
if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 31.5.3"), vulnerable:make_list("lt 31.5.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Products");
}
