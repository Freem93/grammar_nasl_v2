#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201009-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(49126);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3953", "CVE-2009-4324", "CVE-2010-0186", "CVE-2010-0188", "CVE-2010-0190", "CVE-2010-0191", "CVE-2010-0192", "CVE-2010-0193", "CVE-2010-0194", "CVE-2010-0195", "CVE-2010-0196", "CVE-2010-0197", "CVE-2010-0198", "CVE-2010-0199", "CVE-2010-0201", "CVE-2010-0202", "CVE-2010-0203", "CVE-2010-0204", "CVE-2010-1241", "CVE-2010-1285", "CVE-2010-1295", "CVE-2010-1297", "CVE-2010-2168", "CVE-2010-2201", "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205", "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209", "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212");
  script_bugtraq_id(37331, 37758, 38195, 38198, 39417, 39469, 39470, 39505, 39507, 39511, 39514, 39515, 39517, 39518, 39520, 39522, 39523, 39524, 40586, 41230, 41231, 41232, 41234, 41235, 41236, 41237, 41238, 41239, 41240, 41241, 41242, 41243, 41244, 41245);
  script_osvdb_id(27723, 60980, 61690, 62300, 63618, 63751, 63752, 63753, 63754, 63755, 63756, 63757, 63758, 63759, 63760, 63761, 63762, 63763, 63764, 65141, 65909, 65910, 65911, 65912, 65913, 65914, 65915, 65916, 65917, 65918, 65919, 65920, 65921, 65922, 65923);
  script_xref(name:"GLSA", value:"201009-05");

  script_name(english:"GLSA-201009-05 : Adobe Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201009-05
(Adobe Reader: Multiple vulnerabilities)

    Multiple vulnerabilities were discovered in Adobe Reader. For further
    information please consult the CVE entries and the Adobe Security
    Bulletins referenced below.
  
Impact :

    A remote attacker might entice a user to open a specially crafted PDF
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application, or bypass intended
    sandbox restrictions, make cross-domain requests, inject arbitrary web
    script or HTML, or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa10-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201009-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-9.3.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 9.3.4"), vulnerable:make_list("lt 9.3.4"))) flag++;

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
