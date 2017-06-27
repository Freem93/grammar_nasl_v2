#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-14.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28197);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-5334", "CVE-2007-5335", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_osvdb_id(33809, 37995, 38030, 38033, 38034, 38035, 38043, 38044, 42470);
  script_xref(name:"GLSA", value:"200711-14");

  script_name(english:"GLSA-200711-14 : Mozilla Firefox, SeaMonkey, XULRunner: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-14
(Mozilla Firefox, SeaMonkey, XULRunner: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in Mozilla Firefox and
    SeaMonkey. Various errors in the browser engine and the JavaScript
    engine can be exploited to cause a memory corruption (CVE-2007-5339 and
    CVE-2007-5340). Before being used in a request, input passed to the
    user ID when making an HTTP request with digest authentication is not
    properly sanitised (CVE-2007-2292). The titlebar can be hidden by a XUL
    markup language document (CVE-2007-5334). Additionally, an error exists
    in the handling of 'smb:' and 'sftp:' URI schemes on systems with
    gnome-vfs support (CVE-2007-5337). An unspecified error in the handling
    of 'XPCNativeWrappers' and not properly implementing JavaScript
    onUnload() handlers may allow the execution of arbitrary JavaScript
    code (CVE-2007-5338 and CVE-2007-1095). Another error is triggered by
    using the addMicrosummaryGenerator sidebar method to access file: URIs
    (CVE-2007-5335).
  
Impact :

    A remote attacker could exploit these issues to execute arbitrary code,
    gain the privileges of the user running the application, disclose
    sensitive information, conduct phishing attacks, and read and
    manipulate certain data.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-2.0.0.9'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-2.0.0.9'
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-1.1.6'
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-1.1.6'
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/xulrunner-1.8.1.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 2.0.0.9"), vulnerable:make_list("lt 2.0.0.9"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 1.1.6"), vulnerable:make_list("lt 1.1.6"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 1.1.6"), vulnerable:make_list("lt 1.1.6"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner", unaffected:make_list("ge 1.8.1.9"), vulnerable:make_list("lt 1.8.1.9"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 2.0.0.9"), vulnerable:make_list("lt 2.0.0.9"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox / SeaMonkey / XULRunner");
}
