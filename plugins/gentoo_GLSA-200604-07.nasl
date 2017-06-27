#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200604-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21231);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
  script_osvdb_id(22290, 22291, 22705, 23362, 23363, 23364);
  script_xref(name:"GLSA", value:"200604-07");

  script_name(english:"GLSA-200604-07 : Cacti: Multiple vulnerabilities in included ADOdb");
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
"The remote host is affected by the vulnerability described in GLSA-200604-07
(Cacti: Multiple vulnerabilities in included ADOdb)

    Several vulnerabilities have been identified in the copy of ADOdb
    included in Cacti. Andreas Sandblad discovered a dynamic code
    evaluation vulnerability (CVE-2006-0147) and a potential SQL injection
    vulnerability (CVE-2006-0146). Andy Staudacher reported another SQL
    injection vulnerability (CVE-2006-0410), and Gulftech Security
    discovered multiple cross-site-scripting issues (CVE-2006-0806).
  
Impact :

    Remote attackers could trigger these vulnerabilities by sending
    malicious queries to the Cacti web application, resulting in arbitrary
    code execution, database compromise through arbitrary SQL execution,
    and malicious HTML or JavaScript code injection.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200604-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/cacti-0.8.6h_p20060108-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-analyzer/cacti", unaffected:make_list("ge 0.8.6h_p20060108-r2"), vulnerable:make_list("lt 0.8.6h_p20060108-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cacti");
}
