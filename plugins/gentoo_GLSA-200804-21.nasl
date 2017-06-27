#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-21.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32014);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-0071", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243", "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id(26930, 26966, 27034, 28694, 28695, 28696, 28697);
  script_osvdb_id(41487, 41489, 41490, 43979, 44279, 44282, 44283, 51567);
  script_xref(name:"GLSA", value:"200804-21");

  script_name(english:"GLSA-200804-21 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200804-21
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Flash:
    Secunia Research and Zero Day Initiative reported a boundary error
    related to DeclareFunction2 Actionscript tags in SWF files
    (CVE-2007-6019).
    The ISS X-Force and the Zero Day Initiative reported an unspecified
    input validation error that might lead to a buffer overflow
    (CVE-2007-0071).
    Microsoft, UBsecure and JPCERT/CC reported that cross-domain policy
    files are not checked before sending HTTP headers to another domain
    (CVE-2008-1654) and that it does not sufficiently restrict the
    interpretation and usage of cross-domain policy files (CVE-2007-6243).
    The Stanford University and Ernst and Young's Advanced Security Center
    reported that Flash does not pin DNS hostnames to a single IP
    addresses, allowing for DNS rebinding attacks (CVE-2007-5275,
    CVE-2008-1655).
    The Google Security Team and Minded Security Multiple reported multiple
    cross-site scripting vulnerabilities when passing input to Flash
    functions (CVE-2007-6637).
  
Impact :

    A remote attacker could entice a user to open a specially crafted file
    (usually in a web browser), possibly leading to the execution of
    arbitrary code with the privileges of the user running the Adobe Flash
    Player. The attacker could also cause a user's machine to send HTTP
    requests to other hosts, establish TCP sessions with arbitrary hosts,
    bypass the security sandbox model, or conduct Cross-Site Scripting and
    Cross-Site Request Forgery attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-9.0.124.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 189, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 9.0.124.0"), vulnerable:make_list("lt 9.0.124.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Flash Player");
}
