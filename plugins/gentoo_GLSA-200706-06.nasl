#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200706-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25561);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_osvdb_id(34856, 35134, 35135, 35136, 35137, 35138, 35139, 35140);
  script_xref(name:"GLSA", value:"200706-06");

  script_name(english:"GLSA-200706-06 : Mozilla products: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200706-06
(Mozilla products: Multiple vulnerabilities)

    Mozilla developers fixed several bugs involving memory corruption
    through various vectors (CVE-2007-2867, CVE-2007-2868). Additionally,
    several errors leading to crash, memory exhaustion or CPU consumption
    were fixed (CVE-2007-1362, CVE-2007-2869). Finally, errors related to
    the APOP protocol (CVE-2007-1558), XSS prevention (CVE-2007-2870) and
    spoofing prevention (CVE-2007-2871) were fixed.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
    page that will trigger one of the vulnerabilities, possibly leading to
    the execution of arbitrary code or a Denial of Service. It is also
    possible for an attacker to spoof the address bar or other browser
    elements, obtain sensitive APOP information, or perform cross-site
    scripting attacks, leading to the exposure of sensitive information,
    like user credentials.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200706-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-2.0.0.4'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-2.0.0.4'
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-2.0.0.4'
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-2.0.0.4'
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-1.1.2'
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-1.1.2'
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/xulrunner-1.8.1.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/02");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 2.0.0.4"), vulnerable:make_list("lt 2.0.0.4"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 1.1.2"), vulnerable:make_list("lt 1.1.2"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 2.0.0.4", "rge 1.5.0.12"), vulnerable:make_list("lt 2.0.0.4"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 1.1.2"), vulnerable:make_list("lt 1.1.2"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 2.0.0.4", "rge 1.5.0.12"), vulnerable:make_list("lt 2.0.0.4"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner", unaffected:make_list("ge 1.8.1.4"), vulnerable:make_list("lt 1.8.1.4"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 2.0.0.4"), vulnerable:make_list("lt 2.0.0.4"))) flag++;

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
