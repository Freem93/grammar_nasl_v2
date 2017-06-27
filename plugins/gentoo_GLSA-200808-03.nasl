#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200808-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33833);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-1380", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811", "CVE-2008-2933");
  script_bugtraq_id(28818, 29802, 30038, 30242);
  script_osvdb_id(44467, 46421, 46673, 46674, 46675, 46676, 46677, 46678, 46679, 46681, 46682, 46683, 46684, 46685, 46686, 46687, 46688, 47465, 47466);
  script_xref(name:"GLSA", value:"200808-03");

  script_name(english:"GLSA-200808-03 : Mozilla products: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200808-03
(Mozilla products: Multiple vulnerabilities)

    The following vulnerabilities were reported in all mentioned Mozilla
    products:
    TippingPoint's Zero Day Initiative reported that an incorrect integer
    data type is used as a CSS object reference counter, leading to a
    counter overflow and a free() of in-use memory (CVE-2008-2785).
    Igor Bukanov, Jesse Ruderman and Gary Kwong reported crashes in the
    JavaScript engine, possibly triggering memory corruption
    (CVE-2008-2799).
    Devon Hubbard, Jesse Ruderman, and Martijn Wargers reported crashes in
    the layout engine, possibly triggering memory corruption
    (CVE-2008-2798).
    moz_bug_r_a4 reported that XUL documents that include a script from a
    chrome: URI that points to a fastload file would be executed with the
    privileges specified in the file (CVE-2008-2802).
    moz_bug_r_a4 reported that the mozIJSSubScriptLoader.LoadScript()
    function only apply XPCNativeWrappers to scripts loaded from standard
    'chrome:' URIs, which could be the case in third-party add-ons
    (CVE-2008-2803).
    Astabis reported a crash in the block reflow implementation related to
    large images (CVE-2008-2811).
    John G. Myers, Frank Benkstein and Nils Toedtmann reported a weakness
    in the trust model used by Mozilla, that when a user accepts an SSL
    server certificate on the basis of the CN domain name in the DN field,
    the certificate is also regarded as accepted for all domain names in
    subjectAltName:dNSName fields (CVE-2008-2809).
    The following vulnerabilities were reported in Firefox, SeaMonkey and
    XULRunner:
    moz_bug_r_a4 reported that the Same Origin Policy is not properly
    enforced on JavaScript (CVE-2008-2800).
    Collin Jackson and Adam Barth reported that JAR signing is not properly
    implemented, allowing injection of JavaScript into documents within a
    JAR archive (CVE-2008-2801).
    Opera Software reported an error allowing for arbitrary local file
    upload (CVE-2008-2805).
    Daniel Glazman reported that an invalid .properties file for an add-on
    might lead to the usage of uninitialized memory (CVE-2008-2807).
    Masahiro Yamada reported that HTML in 'file://' URLs in directory
    listings is not properly escaped (CVE-2008-2808).
    Geoff reported that the context of Windows Internet shortcut files is
    not correctly identified (CVE-2008-2810).
    The crash vulnerability (CVE-2008-1380) that was previously announced
    in GLSA 200805-18 is now also also resolved in SeaMonkey binary
    ebuilds.
    The following vulnerability was reported in Firefox only:
    Billy Rios reported that the Pipe character in a command-line URI is
    identified as a request to open multiple tabs, allowing to open
    'chrome' and 'file' URIs (CVE-2008-2933).
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
    page or email that will trigger one of the vulnerabilities, possibly
    leading to the execution of arbitrary code or a Denial of Service. It
    is also possible for an attacker to trick a user to upload arbitrary
    files or to accept an invalid certificate for a spoofed website, to
    read uninitialized memory, to violate Same Origin Policy, or to conduct
    Cross-Site Scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200805-18.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200808-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-2.0.0.16'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-2.0.0.16'
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-2.0.0.16'
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-2.0.0.16'
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-1.1.11'
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-1.1.11'
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/xulrunner-1.8.1.16'
    All XULRunner binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/xulrunner-bin-1.8.1.16'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/07");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 2.0.0.16"), vulnerable:make_list("lt 2.0.0.16"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 1.1.11"), vulnerable:make_list("lt 1.1.11"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner-bin", unaffected:make_list("ge 1.8.1.16"), vulnerable:make_list("lt 1.8.1.16"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 2.0.0.16"), vulnerable:make_list("lt 2.0.0.16"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 1.1.11"), vulnerable:make_list("lt 1.1.11"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 2.0.0.16"), vulnerable:make_list("lt 2.0.0.16"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner", unaffected:make_list("ge 1.8.1.16"), vulnerable:make_list("lt 1.8.1.16"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 2.0.0.16"), vulnerable:make_list("lt 2.0.0.16"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla products");
}
