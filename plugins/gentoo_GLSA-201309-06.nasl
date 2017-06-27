#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(69889);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2012-5248", "CVE-2012-5249", "CVE-2012-5250", "CVE-2012-5251", "CVE-2012-5252", "CVE-2012-5253", "CVE-2012-5254", "CVE-2012-5255", "CVE-2012-5256", "CVE-2012-5257", "CVE-2012-5258", "CVE-2012-5259", "CVE-2012-5260", "CVE-2012-5261", "CVE-2012-5262", "CVE-2012-5263", "CVE-2012-5264", "CVE-2012-5265", "CVE-2012-5266", "CVE-2012-5267", "CVE-2012-5268", "CVE-2012-5269", "CVE-2012-5270", "CVE-2012-5271", "CVE-2012-5272", "CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277", "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280", "CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678", "CVE-2013-0504", "CVE-2013-0630", "CVE-2013-0633", "CVE-2013-0634", "CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642", "CVE-2013-0643", "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0646", "CVE-2013-0647", "CVE-2013-0648", "CVE-2013-0649", "CVE-2013-0650", "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368", "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1371", "CVE-2013-1372", "CVE-2013-1373", "CVE-2013-1374", "CVE-2013-1375", "CVE-2013-1378", "CVE-2013-1379", "CVE-2013-1380", "CVE-2013-2555", "CVE-2013-2728", "CVE-2013-3343", "CVE-2013-3344", "CVE-2013-3345", "CVE-2013-3347", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363", "CVE-2013-5324");
  script_osvdb_id(86025, 86026, 86027, 86028, 86029, 86030, 86031, 86032, 86033, 86034, 86035, 86036, 86037, 86038, 86039, 86040, 86041, 86042, 86043, 86044, 86045, 86046, 86047, 86048, 86049, 87064, 87065, 87066, 87067, 87068, 87069, 87070, 88353, 88354, 88356, 88969, 89936, 89937, 90095, 90096, 90097, 90098, 90099, 90100, 90101, 90102, 90103, 90104, 90105, 90106, 90107, 90108, 90109, 90110, 90111, 90612, 90613, 90614, 91158, 91159, 91160, 91161, 91203, 92141, 92142, 92143, 93322, 94128, 94988, 94989, 94990, 97050, 97051, 97052, 97053);
  script_xref(name:"GLSA", value:"201309-06");

  script_name(english:"GLSA-201309-06 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-06
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple unspecified vulnerabilities have been discovered in Adobe Flash
      Player. Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open specially crafted SWF
      content, possibly resulting in execution of arbitrary code with the
      privileges of the process or a Denial of Service condition. Furthermore,
      a remote attacker may be able to bypass access restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-plugins/adobe-flash-11.2.202.310'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Regular Expression Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/14");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 11.2.202.310"), vulnerable:make_list("lt 11.2.202.310"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Flash Player");
}
