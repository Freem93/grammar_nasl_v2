#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201604-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(90744);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2015-8711", "CVE-2015-8712", "CVE-2015-8713", "CVE-2015-8714", "CVE-2015-8715", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8719", "CVE-2015-8720", "CVE-2015-8721", "CVE-2015-8722", "CVE-2015-8723", "CVE-2015-8724", "CVE-2015-8725", "CVE-2015-8726", "CVE-2015-8727", "CVE-2015-8728", "CVE-2015-8729", "CVE-2015-8730", "CVE-2015-8731", "CVE-2015-8732", "CVE-2015-8733", "CVE-2015-8734", "CVE-2015-8735", "CVE-2015-8736", "CVE-2015-8737", "CVE-2015-8738", "CVE-2015-8739", "CVE-2015-8740", "CVE-2015-8741", "CVE-2015-8742", "CVE-2016-2521", "CVE-2016-2522", "CVE-2016-2523", "CVE-2016-2524", "CVE-2016-2525", "CVE-2016-2526", "CVE-2016-2527", "CVE-2016-2528", "CVE-2016-2529", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532");
  script_xref(name:"GLSA", value:"201604-05");

  script_name(english:"GLSA-201604-05 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201604-05
(Wireshark: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Wireshark. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    Remote attackers could cause Denial of Service and local attackers could
      escalate privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201604-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-2.0.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 2.0.2"), vulnerable:make_list("lt 2.0.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Wireshark");
}
