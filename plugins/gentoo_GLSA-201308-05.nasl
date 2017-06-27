#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201308-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(69500);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 14:19:46 $");

  script_cve_id("CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0043", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-0068", "CVE-2012-3548", "CVE-2012-4048", "CVE-2012-4049", "CVE-2012-4285", "CVE-2012-4286", "CVE-2012-4287", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4294", "CVE-2012-4295", "CVE-2012-4296", "CVE-2012-4297", "CVE-2012-4298", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083", "CVE-2013-4920", "CVE-2013-4921", "CVE-2013-4922", "CVE-2013-4923", "CVE-2013-4924", "CVE-2013-4925", "CVE-2013-4926", "CVE-2013-4927", "CVE-2013-4928", "CVE-2013-4929", "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-4936");
  script_bugtraq_id(51368, 51710, 54649, 55035, 55284, 59992, 59994, 59995, 59996, 59997, 59998, 59999, 60001, 60002, 60021, 60495, 60498, 60499, 60500, 60501, 60502, 60503, 60504, 60505, 60506, 60535, 60547, 60549, 61471);
  script_osvdb_id(78256, 78257, 78258, 78656, 78657, 78658, 84260, 84261, 84776, 84777, 84778, 84779, 84780, 84781, 84782, 84783, 84784, 84785, 84786, 84787, 84788, 85092, 93503, 93508, 93509, 93510, 94086, 94087, 94088, 94090, 94091, 94092, 94093, 94244, 94245, 94246, 95708, 95709, 95710, 95713, 95714, 95715, 95716, 95718, 95719, 95720, 95721, 95722, 95724, 95725, 95726, 95727);
  script_xref(name:"GLSA", value:"201308-05");

  script_name(english:"GLSA-201308-05 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201308-05
(Wireshark: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Wireshark. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201308-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark 1.10 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.10.1'
    All Wireshark 1.8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.8.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 1.10.1", "rge 1.8.9"), vulnerable:make_list("lt 1.10.1"))) flag++;

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
