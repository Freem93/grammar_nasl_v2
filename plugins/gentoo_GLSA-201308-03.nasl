#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201308-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(69454);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2012-1525", "CVE-2012-1530", "CVE-2012-2049", "CVE-2012-2050", "CVE-2012-2051", "CVE-2012-4147", "CVE-2012-4148", "CVE-2012-4149", "CVE-2012-4150", "CVE-2012-4151", "CVE-2012-4152", "CVE-2012-4153", "CVE-2012-4154", "CVE-2012-4155", "CVE-2012-4156", "CVE-2012-4157", "CVE-2012-4158", "CVE-2012-4159", "CVE-2012-4160", "CVE-2012-4363", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603", "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607", "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611", "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615", "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619", "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623", "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627", "CVE-2013-0640", "CVE-2013-0641", "CVE-2013-2549", "CVE-2013-2550", "CVE-2013-2718", "CVE-2013-2719", "CVE-2013-2720", "CVE-2013-2721", "CVE-2013-2722", "CVE-2013-2723", "CVE-2013-2724", "CVE-2013-2725", "CVE-2013-2726", "CVE-2013-2727", "CVE-2013-2729", "CVE-2013-2730", "CVE-2013-2731", "CVE-2013-2732", "CVE-2013-2733", "CVE-2013-2734", "CVE-2013-2735", "CVE-2013-2736", "CVE-2013-2737", "CVE-2013-3337", "CVE-2013-3338", "CVE-2013-3339", "CVE-2013-3340", "CVE-2013-3341", "CVE-2013-3342");
  script_bugtraq_id(55005, 55006, 55008, 55010, 55011, 55012, 55013, 55015, 55016, 55017, 55018, 55019, 55020, 55021, 55024, 55026, 55027, 55055, 57263, 57264, 57265, 57268, 57269, 57270, 57272, 57273, 57274, 57275, 57276, 57277, 57282, 57283, 57284, 57285, 57286, 57287, 57289, 57290, 57291, 57292, 57293, 57294, 57295, 57296, 57297, 57931, 57947, 58398, 58568, 59902, 59903, 59904, 59905, 59906, 59907, 59908, 59909, 59910, 59911, 59912, 59913, 59914, 59915, 59916, 59917, 59918, 59919, 59920, 59921, 59923, 59925, 59926, 59927, 59930);
  script_osvdb_id(84613, 84614, 84615, 84618, 84619, 84620, 84621, 84622, 84623, 84624, 84625, 84626, 84627, 84628, 84629, 84630, 84631, 84632, 84660, 88970, 88971, 88972, 88973, 88974, 88975, 88976, 88977, 88978, 88979, 88980, 88981, 88982, 88983, 88984, 88985, 88986, 88987, 88988, 88989, 88990, 88991, 88992, 88993, 88994, 88995, 88996, 90169, 90170, 91201, 91202, 93335, 93336, 93337, 93338, 93339, 93340, 93341, 93342, 93343, 93344, 93345, 93346, 93347, 93348, 93349, 93350, 93351, 93352, 93353, 93354, 93355, 93356, 93357, 93358, 93359);
  script_xref(name:"GLSA", value:"201308-03");

  script_name(english:"GLSA-201308-03 : Adobe Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201308-03
(Adobe Reader: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Reader. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted PDF
      file, possibly resulting in arbitrary code execution or a Denial of
      Service condition. A local attacker could gain privileges via unspecified
      vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201308-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/acroread-9.5.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/23");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 9.5.5"), vulnerable:make_list("lt 9.5.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Reader");
}
