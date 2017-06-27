#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200908-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40520);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-1862", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
  script_osvdb_id(56282, 56771, 56772, 56773, 56774, 56775, 56776, 56777, 56778);
  script_xref(name:"GLSA", value:"200908-04");

  script_name(english:"GLSA-200908-04 : Adobe products: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200908-04
(Adobe products: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in Adobe Flash Player:
    lakehu of Tencent Security Center reported an unspecified
    memory corruption vulnerability (CVE-2009-1862).
    Mike Wroe
    reported an unspecified vulnerability, related to 'privilege
    escalation' (CVE-2009-1863).
    An anonymous researcher through
    iDefense reported an unspecified heap-based buffer overflow
    (CVE-2009-1864).
    Chen Chen of Venustech reported an
    unspecified 'NULL pointer vulnerability' (CVE-2009-1865).
    Chen
    Chen of Venustech reported an unspecified stack-based buffer overflow
    (CVE-2009-1866).
    Joran Benker reported that Adobe Flash Player
    facilitates 'clickjacking' attacks (CVE-2009-1867).
    Jun Mao of
    iDefense reported a heap-based buffer overflow, related to URL parsing
    (CVE-2009-1868).
    Roee Hay of IBM Rational Application Security
    reported an unspecified integer overflow (CVE-2009-1869).
    Gareth Heyes and Microsoft Vulnerability Research reported that the
    sandbox in Adobe Flash Player allows for information disclosure, when
    'SWFs are saved to the hard drive' (CVE-2009-1870).
  
Impact :

    A remote attacker could entice a user to open a specially crafted PDF
    file or website containing Adobe Flash (SWF) contents, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application, or a Denial of Service (application
    crash). Furthermore, a remote attacker could trick a user into clicking
    a button on a dialog by supplying a specially crafted SWF file and
    disclose sensitive information by exploiting a sandbox issue.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200908-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-10.0.32.18'
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-9.1.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(59, 94, 119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 9.1.3"), vulnerable:make_list("lt 9.1.3"))) flag++;
if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 10.0.32.18"), vulnerable:make_list("lt 10.0.32.18"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe products");
}
