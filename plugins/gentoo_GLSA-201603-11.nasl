#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(89904);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/11/14 14:40:46 $");

  script_cve_id("CVE-2015-0437", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0486", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2659", "CVE-2015-2664", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4734", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4760", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4810", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4901", "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4906", "CVE-2015-4908", "CVE-2015-4911", "CVE-2015-4916", "CVE-2015-7840");
  script_xref(name:"GLSA", value:"201603-11");
  script_xref(name:"IAVA", value:"2015-A-0254");

  script_name(english:"GLSA-201603-11 : Oracle JRE/JDK: Multiple vulnerabilities (Logjam)");
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
"The remote host is affected by the vulnerability described in GLSA-201603-11
(Oracle JRE/JDK: Multiple vulnerabilities)

    Multiple vulnerabilities exist in both Oracle&rsquo;s JRE and JDK.  Please
      review the referenced CVE&rsquo;s for additional information.
  
Impact :

    Remote attackers could gain access to information, remotely execute
      arbitrary code, and cause Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JRE Users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jre-bin-1.8.0.72'
    All Oracle JDK Users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jdk-bin-1.8.0.72'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.8.0.72 "), vulnerable:make_list("lt 1.8.0.72 "))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.8.0.72 "), vulnerable:make_list("lt 1.8.0.72 "))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle JRE/JDK");
}
