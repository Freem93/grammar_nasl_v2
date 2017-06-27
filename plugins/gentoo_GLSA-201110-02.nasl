#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56426);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2010-2283", "CVE-2010-2284", "CVE-2010-2285", "CVE-2010-2286", "CVE-2010-2287", "CVE-2010-2992", "CVE-2010-2993", "CVE-2010-2994", "CVE-2010-2995", "CVE-2010-3133", "CVE-2010-3445", "CVE-2010-4300", "CVE-2010-4301", "CVE-2010-4538", "CVE-2011-0024", "CVE-2011-0444", "CVE-2011-0445", "CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1138", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1142", "CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1591", "CVE-2011-1592", "CVE-2011-1956", "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597", "CVE-2011-2698", "CVE-2011-3266", "CVE-2011-3360", "CVE-2011-3482", "CVE-2011-3483");
  script_osvdb_id(65371, 65372, 65373, 65374, 65375, 66792, 66793, 67191, 67504, 68129, 69354, 69355, 70244, 70402, 70403, 71548, 71549, 71550, 71551, 71552, 71553, 71554, 71555, 71556, 71846, 71847, 71848, 72974, 72975, 72976, 72977, 72978, 72979, 73403, 73687, 74731, 74732, 75346, 75347, 75348);
  script_xref(name:"GLSA", value:"201110-02");

  script_name(english:"GLSA-201110-02 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-02
(Wireshark: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Wireshark. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could send specially crafted packets on a network
      being monitored by Wireshark, entice a user to open a malformed packet
      trace file using Wireshark, or deploy a specially crafted Lua script for
      use by Wireshark, possibly resulting in the execution of arbitrary code,
      or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.4.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark console.lua Pre-Loading Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/10");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 1.4.9"), vulnerable:make_list("lt 1.4.9"))) flag++;

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
