#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201610-09.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(94420);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/14 14:40:46 $");

  script_cve_id("CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137", "CVE-2016-5138", "CVE-2016-5139", "CVE-2016-5140", "CVE-2016-5141", "CVE-2016-5142", "CVE-2016-5143", "CVE-2016-5144", "CVE-2016-5145", "CVE-2016-5146", "CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167", "CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173", "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-5177", "CVE-2016-5178", "CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192", "CVE-2016-5193", "CVE-2016-5194");
  script_xref(name:"GLSA", value:"201610-09");

  script_name(english:"GLSA-201610-09 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201610-09
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
    value:"https://security.gentoo.org/glsa/201610-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-54.0.2840.59'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/31");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 54.0.2840.59"), vulnerable:make_list("lt 54.0.2840.59"))) flag++;

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
