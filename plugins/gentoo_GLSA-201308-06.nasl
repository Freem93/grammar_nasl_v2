#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201308-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(69508);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492", "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496", "CVE-2012-0540", "CVE-2012-0553", "CVE-2012-0572", "CVE-2012-0574", "CVE-2012-0578", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1696", "CVE-2012-1697", "CVE-2012-1702", "CVE-2012-1703", "CVE-2012-1705", "CVE-2012-1734", "CVE-2012-2102", "CVE-2012-2122", "CVE-2012-2749", "CVE-2012-3150", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197", "CVE-2012-5060", "CVE-2012-5096", "CVE-2012-5611", "CVE-2012-5612", "CVE-2012-5613", "CVE-2012-5614", "CVE-2012-5615", "CVE-2012-5627", "CVE-2013-0367", "CVE-2013-0368", "CVE-2013-0371", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0386", "CVE-2013-0389", "CVE-2013-1492", "CVE-2013-1502", "CVE-2013-1506", "CVE-2013-1511", "CVE-2013-1512", "CVE-2013-1521", "CVE-2013-1523", "CVE-2013-1526", "CVE-2013-1531", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-1566", "CVE-2013-1567", "CVE-2013-1570", "CVE-2013-1623", "CVE-2013-2375", "CVE-2013-2376", "CVE-2013-2378", "CVE-2013-2381", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392", "CVE-2013-2395", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3808");
  script_bugtraq_id(51271, 51488, 51493, 51502, 51503, 51504, 51505, 51506, 51507, 51508, 51509, 51510, 51511, 51512, 51513, 51514, 51515, 51516, 51517, 51518, 51519, 51520, 51521, 51522, 51523, 51524, 51525, 51526, 52931, 53058, 53061, 53064, 53067, 53071, 53074, 53911, 54540, 54547, 54551, 55120, 55990, 56003, 56005, 56017, 56018, 56021, 56027, 56028, 56036, 56041, 56766, 56768, 56769, 56771, 56776, 56837, 57334, 57385, 57388, 57391, 57397, 57400, 57405, 57408, 57410, 57411, 57412, 57414, 57415, 57416, 57417, 57418, 57780, 58594, 58595, 59173, 59180, 59188, 59196, 59201, 59202, 59205, 59207, 59209, 59210, 59211, 59215, 59216, 59217, 59218, 59223, 59224, 59225, 59227, 59229, 59232, 59237, 59239, 59242, 61227, 61244, 61260);
  script_osvdb_id(78368, 78369, 78370, 78371, 78372, 78373, 78374, 78375, 78376, 78377, 78378, 78379, 78380, 78381, 78382, 78383, 78384, 78385, 78386, 78387, 78388, 78389, 78390, 78391, 78392, 78393, 78394, 81059, 81373, 81374, 81375, 81376, 81377, 81378, 82804, 83976, 83979, 83980, 84755, 86260, 86261, 86262, 86264, 86265, 86267, 86268, 86271, 86272, 86273, 88064, 88065, 88066, 88067, 88118, 88415, 89250, 89251, 89252, 89253, 89254, 89255, 89256, 89257, 89258, 89259, 89260, 89261, 89262, 89263, 89264, 89265, 91534, 91536, 92462, 92463, 92464, 92465, 92466, 92467, 92468, 92469, 92470, 92471, 92472, 92473, 92474, 92475, 92476, 92477, 92478, 92479, 92480, 92481, 92482, 92483, 92484, 92485, 95325, 95328, 95330);
  script_xref(name:"GLSA", value:"201308-06");

  script_name(english:"GLSA-201308-06 : MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201308-06
(MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could send a specially crafted request, possibly
      resulting in execution of arbitrary code with the privileges of the
      application or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201308-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.1.70'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle MySQL for Microsoft Windows FILE Privilege Abuse');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.1.70"), vulnerable:make_list("lt 5.1.70"))) flag++;

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
