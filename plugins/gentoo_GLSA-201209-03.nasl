#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62236);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/19 13:38:50 $");

  script_cve_id("CVE-2011-1398", "CVE-2011-3379", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0788", "CVE-2012-0789", "CVE-2012-0830", "CVE-2012-0831", "CVE-2012-1172", "CVE-2012-1823", "CVE-2012-2143", "CVE-2012-2311", "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386", "CVE-2012-2688", "CVE-2012-3365", "CVE-2012-3450");
  script_bugtraq_id(47545, 49754, 50907, 51193, 51806, 51830, 51952, 51954, 52043, 53388, 53403, 53729, 54612, 54638, 54777, 55297);
  script_osvdb_id(72399, 75713, 77446, 78115, 78676, 78819, 79016, 79017, 79332, 81633, 81791, 82213, 82509, 82510, 82577, 82578, 82931, 84100, 84126, 85086);
  script_xref(name:"GLSA", value:"201209-03");
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"GLSA-201209-03 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-03
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could execute arbitrary code with the privileges of
      the process, cause a Denial of Service condition, obtain sensitive
      information, create arbitrary files, conduct directory traversal attacks,
      bypass protection mechanisms, or perform further attacks with unspecified
      impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201209-03"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2012-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.15'
    All PHP users on ARM should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.4.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.3.15", "ge 5.4.5"), vulnerable:make_list("lt 5.3.15", "lt 5.4.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
