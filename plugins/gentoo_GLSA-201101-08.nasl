#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201101-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(51657);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/07/18 14:06:55 $");

  script_cve_id("CVE-2010-2883", "CVE-2010-2884", "CVE-2010-2887", "CVE-2010-2889", "CVE-2010-2890", "CVE-2010-3619", "CVE-2010-3620", "CVE-2010-3621", "CVE-2010-3622", "CVE-2010-3625", "CVE-2010-3626", "CVE-2010-3627", "CVE-2010-3628", "CVE-2010-3629", "CVE-2010-3630", "CVE-2010-3632", "CVE-2010-3654", "CVE-2010-3656", "CVE-2010-3657", "CVE-2010-3658", "CVE-2010-4091");
  script_bugtraq_id(43057, 43205, 43722, 43723, 43724, 43725, 43726, 43727, 43729, 43730, 43732, 43734, 43735, 43737, 43738, 43740, 43741, 43744, 43746, 44504, 44638);
  script_osvdb_id(67849, 68024, 68412, 68416, 68418, 68419, 68420, 68421, 68422, 68425, 68426, 68427, 68428, 68429, 68430, 68432, 68433, 68434, 68435, 68932, 69005);
  script_xref(name:"GLSA", value:"201101-08");

  script_name(english:"GLSA-201101-08 : Adobe Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201101-08
(Adobe Reader: Multiple vulnerabilities)

    Multiple vulnerabilities were discovered in Adobe Reader. For further
    information please consult the CVE entries and the Adobe Security
    Bulletins referenced below.
  
Impact :

    A remote attacker might entice a user to open a specially crafted PDF
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201101-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-9.4.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-971");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 9.4.1"), vulnerable:make_list("lt 9.4.1"))) flag++;

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
