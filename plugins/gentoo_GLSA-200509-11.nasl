#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200509-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19810);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");
  script_osvdb_id(19255);
  script_xref(name:"GLSA", value:"200509-11");

  script_name(english:"GLSA-200509-11 : Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200509-11
(Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities)

    The Mozilla Suite and Firefox are both vulnerable to the following
    issues:
    Tom Ferris reported a heap overflow in IDN-enabled browsers with
    malicious Host: headers (CAN-2005-2871).
    'jackerror' discovered a heap overrun in XBM image processing
    (CAN-2005-2701).
    Mats Palmgren reported a potentially exploitable stack corruption
    using specific Unicode sequences (CAN-2005-2702).
    Georgi Guninski discovered an integer overflow in the JavaScript
    engine (CAN-2005-2705)
    Other issues ranging from DOM object spoofing to request header
    spoofing were also found and fixed in the latest versions
    (CAN-2005-2703, CAN-2005-2704, CAN-2005-2706, CAN-2005-2707).
    The Gecko engine in itself is also affected by some of these issues and
    has been updated as well.
  
Impact :

    A remote attacker could setup a malicious site and entice a victim to
    visit it, potentially resulting in arbitrary code execution with the
    victim's privileges or facilitated spoofing of known websites.
  
Workaround :

    There is no known workaround for all the issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200509-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-1.0.7-r2'
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.12-r2'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-1.0.7'
    All Mozilla Suite binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.12'
    All Gecko library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/gecko-sdk-1.7.12'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gecko-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-libs/gecko-sdk", unaffected:make_list("ge 1.7.12"), vulnerable:make_list("lt 1.7.12"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 1.0.7"), vulnerable:make_list("lt 1.0.7"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.12-r2"), vulnerable:make_list("lt 1.7.12-r2"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.12"), vulnerable:make_list("lt 1.7.12"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 1.0.7-r2"), vulnerable:make_list("lt 1.0.7-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite / Mozilla Firefox");
}
