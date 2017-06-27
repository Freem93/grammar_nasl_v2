#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39777);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512", "CVE-2009-0888", "CVE-2009-0889", "CVE-2009-1492", "CVE-2009-1493", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857", "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861", "CVE-2009-2028");
  script_bugtraq_id(34736, 34740, 35274, 35282, 35289, 35293, 35294, 35295, 35296, 35298, 35299, 35300, 35302, 35303);
  script_osvdb_id(56106, 56107, 56108, 56109, 56110, 56111, 56112, 56113, 56114, 56115, 56116, 56117, 56118, 56119);
  script_xref(name:"GLSA", value:"200907-06");

  script_name(english:"GLSA-200907-06 : Adobe Reader: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200907-06
(Adobe Reader: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been reported in Adobe Reader:
    Alin Rad Pop of Secunia Research reported a heap-based buffer
    overflow in the JBIG2 filter (CVE-2009-0198).
    Mark Dowd of the IBM Internet Security Systems X-Force and
    Nicolas Joly of VUPEN Security reported multiple heap-based buffer
    overflows in the JBIG2 filter (CVE-2009-0509, CVE-2009-0510,
    CVE-2009-0511, CVE-2009-0512, CVE-2009-0888, CVE-2009-0889)
    Arr1val reported that multiple methods in the JavaScript API
    might lead to memory corruption when called with crafted arguments
    (CVE-2009-1492, CVE-2009-1493).
    An anonymous researcher reported a stack-based buffer overflow related
    to U3D model files with a crafted extension block (CVE-2009-1855).
    Jun Mao and Ryan Smith of iDefense Labs reported an integer overflow
    related to the FlateDecode filter, which triggers a heap-based buffer
    overflow (CVE-2009-1856).
    Haifei Li of Fortinet's FortiGuard Global Security Research Team
    reported a memory corruption vulnerability related to TrueType fonts
    (CVE-2009-1857).
    The Apple Product Security Team reported a memory corruption
    vulnerability in the JBIG2 filter (CVE-2009-1858).
    Matthew Watchinski of Sourcefire VRT reported an unspecified memory
    corruption (CVE-2009-1859).
    Will Dormann of CERT reported multiple heap-based buffer overflows when
    processing JPX (aka JPEG2000) stream that trigger heap memory
    corruption (CVE-2009-1861).
    Multiple unspecified vulnerabilities have been discovered
    (CVE-2009-2028).
  
Impact :

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-8.1.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/13");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 8.1.6"), vulnerable:make_list("lt 8.1.6"))) flag++;

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
