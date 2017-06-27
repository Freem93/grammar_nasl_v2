#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-23.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70183);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0765", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0784", "CVE-2013-0787", "CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697", "CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705", "CVE-2013-1707", "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717", "CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1722", "CVE-2013-1723", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1726", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");
  script_bugtraq_id(57193, 57194, 57195, 57196, 57197, 57198, 57199, 57203, 57204, 57205, 57207, 57209, 57211, 57213, 57215, 57217, 57218, 57228, 57232, 57234, 57235, 57236, 57238, 57240, 57241, 57244, 57260, 58034, 58036, 58037, 58038, 58040, 58041, 58042, 58043, 58044, 58047, 58048, 58049, 58050, 58051, 58391, 58819, 58821, 58824, 58825, 58826, 58827, 58828, 58831, 58835, 58836, 58837, 59855, 59858, 59859, 59860, 59861, 59862, 59863, 59864, 59865, 59868, 59869, 60765, 60766, 60776, 60777, 60778, 60783, 60784, 60787, 61864, 61867, 61871, 61872, 61873, 61874, 61875, 61876, 61877, 61878, 61882, 61896, 61900, 62460, 62462, 62463, 62464, 62465, 62466, 62467, 62468, 62469, 62472, 62473, 62475, 62478, 62479, 62482);
  script_osvdb_id(88997, 88998, 88999, 89000, 89001, 89002, 89003, 89004, 89005, 89006, 89008, 89009, 89010, 89011, 89012, 89013, 89014, 89015, 89016, 89017, 89018, 89019, 89020, 89021, 89022, 89023, 89024, 90418, 90419, 90420, 90421, 90422, 90423, 90424, 90425, 90426, 90427, 90428, 90429, 90430, 90431, 90928, 91874, 91875, 91876, 91878, 91879, 91880, 91881, 91882, 91883, 91885, 91886, 93422, 93423, 93424, 93426, 93427, 93429, 93430, 93431, 93432, 93433, 93434, 94578, 94581, 94582, 94583, 94584, 94587, 94589, 94591, 96010, 96011, 96012, 96013, 96014, 96016, 96017, 96018, 96019, 96020, 96021, 96022, 96023, 97387, 97388, 97389, 97390, 97391, 97392, 97395, 97397, 97398, 97399, 97400, 97401, 97402, 97403, 97404);
  script_xref(name:"GLSA", value:"201309-23");

  script_name(english:"GLSA-201309-23 : Mozilla Products: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-23
(Mozilla Products: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox,
      Thunderbird, and SeaMonkey. Please review the CVE identifiers referenced
      below for details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page or email, possibly resulting in execution of arbitrary code or a
      Denial of Service condition. Further, a remote attacker could conduct XSS
      attacks, spoof URLs, bypass address space layout randomization, conduct
      clickjacking attacks, obtain potentially sensitive information, bypass
      access restrictions, modify the local filesystem, or conduct other
      unspecified attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-17.0.9'
    All users of the Mozilla Firefox binary package should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-17.0.9'
    All Mozilla Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-17.0.9'
    All users of the Mozilla Thunderbird binary package should upgrade to
      the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-17.0.9'
    All SeaMonkey users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-2.21'
    All users of the Mozilla SeaMonkey binary package should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-2.21'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 2.21"), vulnerable:make_list("lt 2.21"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 17.0.9"), vulnerable:make_list("lt 17.0.9"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 17.0.9"), vulnerable:make_list("lt 17.0.9"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 17.0.9"), vulnerable:make_list("lt 17.0.9"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 2.21"), vulnerable:make_list("lt 2.21"))) flag++;
if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 17.0.9"), vulnerable:make_list("lt 17.0.9"))) flag++;

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
