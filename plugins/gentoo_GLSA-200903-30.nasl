#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200903-30.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35943);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5178", "CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681", "CVE-2008-5682", "CVE-2008-5683", "CVE-2009-0914");
  script_osvdb_id(49882, 50951, 50952, 50953, 50954, 51047, 51481);
  script_xref(name:"GLSA", value:"200903-30");

  script_name(english:"GLSA-200903-30 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200903-30
(Opera: Multiple vulnerabilities)

    Multiple vulnerabilities were discovered in Opera:
    Vitaly McLain reported a heap-based buffer overflow when processing
    host names in file:// URLs (CVE-2008-5178).
    Alexios Fakos reported a vulnerability in the HTML parsing engine
    when processing web pages that trigger an invalid pointer calculation
    and heap corruption (CVE-2008-5679).
    Red XIII reported that certain text-area contents can be
    manipulated to cause a buffer overlow (CVE-2008-5680).
    David Bloom discovered that unspecified 'scripted URLs' are not
    blocked during the feed preview (CVE-2008-5681).
    Robert Swiecki of the Google Security Team reported a Cross-site
    scripting vulnerability (CVE-2008-5682).
    An unspecified vulnerability reveals random data
    (CVE-2008-5683).
    Tavis Ormandy of the Google Security Team reported a vulnerability
    when processing JPEG images that may corrupt memory
    (CVE-2009-0914).
  
Impact :

    A remote attacker could entice a user to open a specially crafted JPEG
    image to cause a Denial of Service or execute arbitrary code, to
    process an overly long file:// URL or to open a specially crafted web
    page to execute arbitrary code. He could also read existing
    subscriptions and force subscriptions to arbitrary feed URLs, as well
    as inject arbitrary web script or HTML via built-in XSLT templates.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200903-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.64'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(79, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/17");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 9.64"), vulnerable:make_list("lt 9.64"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
