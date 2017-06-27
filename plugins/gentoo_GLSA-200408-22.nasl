#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14578);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0758", "CVE-2004-0763");
  script_osvdb_id(7939, 8310, 8312, 8313, 8314, 8315, 8316, 8326);
  script_xref(name:"GLSA", value:"200408-22");

  script_name(english:"GLSA-200408-22 : Mozilla, Firefox, Thunderbird, Galeon, Epiphany: New releases fix vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200408-22
(Mozilla, Firefox, Thunderbird, Galeon, Epiphany: New releases fix vulnerabilities)

    Mozilla, Galeon, Epiphany, Mozilla Firefox and Mozilla Thunderbird
    contain the following vulnerabilities:
    All Mozilla tools use libpng for graphics. This library contains a
    buffer overflow which may lead to arbitrary code execution.
    If a user imports a forged Certificate Authority (CA) certificate,
    it may overwrite and corrupt the valid CA already installed on the
    machine.
    Mozilla, Mozilla Firefox, and other gecko-based browsers also contain a
    bug in their caching which may allow the SSL icon to remain visible,
    even when the site in question is an insecure site.
  
Impact :

    Users of Mozilla, Mozilla Firefox, and other gecko-based browsers are
    susceptible to SSL certificate spoofing, a Denial of Service against
    legitimate SSL sites, crashes, and arbitrary code execution. Users of
    Mozilla Thunderbird are susceptible to crashes and arbitrary code
    execution via malicious e-mails.
  
Workaround :

    There is no known workaround for most of these vulnerabilities. All
    users are advised to upgrade to the latest available version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv your-version
    # emerge your-version"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 0.9.3"), vulnerable:make_list("lt 0.9.3"))) flag++;
if (qpkg_check(package:"www-client/galeon", unaffected:make_list("ge 1.3.17"), vulnerable:make_list("lt 1.3.17"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 0.7.3"), vulnerable:make_list("lt 0.7.3"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.2"), vulnerable:make_list("lt 1.7.2"))) flag++;
if (qpkg_check(package:"www-client/epiphany", unaffected:make_list("ge 1.2.7-r1"), vulnerable:make_list("lt 1.2.7-r1"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.2"), vulnerable:make_list("lt 1.7.2"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 0.7.3"), vulnerable:make_list("lt 0.7.3"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 0.9.3"), vulnerable:make_list("lt 0.9.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla / Firefox / Thunderbird / Galeon / Epiphany");
}
