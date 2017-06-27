#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200709-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(26117);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3698", "CVE-2007-3716", "CVE-2007-3922", "CVE-2007-4381");
  script_bugtraq_id(24004, 24846, 25054, 25340);
  script_osvdb_id(36199, 36200, 36201, 36202, 36488, 36662, 36663, 36664, 37766);
  script_xref(name:"GLSA", value:"200709-15");

  script_name(english:"GLSA-200709-15 : BEA JRockit: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200709-15
(BEA JRockit: Multiple vulnerabilities)

    An integer overflow vulnerability exists in the embedded ICC profile
    image parser (CVE-2007-2788), an unspecified vulnerability exists in
    the font parsing implementation (CVE-2007-4381), and an error exists
    when processing XSLT stylesheets contained in XSLT Transforms in XML
    signatures (CVE-2007-3716), among other vulnerabilities.
  
Impact :

    A remote attacker could trigger the integer overflow to execute
    arbitrary code or crash the JVM through a specially crafted file. Also,
    an attacker could perform unauthorized actions via an applet that
    grants certain privileges to itself because of the font parsing
    vulnerability. The error when processing XSLT stylesheets can be
    exploited to execute arbitrary code. Other vulnerabilities could lead
    to establishing restricted network connections to certain services,
    Cross Site Scripting and Denial of Service attacks.
  
Workaround :

    There is no known workaround at this time for all these
    vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200709-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BEA JRockit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/jrockit-jdk-bin-1.5.0.11_p1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:jrockit-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/jrockit-jdk-bin", unaffected:make_list("ge 1.5.0.11_p1"), vulnerable:make_list("lt 1.5.0.11_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BEA JRockit");
}
