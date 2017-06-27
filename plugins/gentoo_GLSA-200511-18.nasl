#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20262);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2005-3347", "CVE-2005-3348");
  script_osvdb_id(20821, 21159);
  script_xref(name:"GLSA", value:"200511-18");

  script_name(english:"GLSA-200511-18 : phpSysInfo: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200511-18
(phpSysInfo: Multiple vulnerabilities)

    Christopher Kunz from the Hardened-PHP Project discovered
    that phpSysInfo is vulnerable to local file inclusion, cross-site
    scripting and a HTTP Response Splitting attacks.
  
Impact :

    A local attacker may exploit the file inclusion vulnerability by
    sending malicious requests, causing the execution of arbitrary code
    with the rights of the user running the web server. A remote attacker
    could exploit the vulnerability to disclose local file content.
    Furthermore, the cross-site scripting issues gives a remote attacker
    the ability to inject and execute malicious script code in the user's
    browser context or to steal cookie-based authentication credentials.
    The HTTP response splitting issue give an attacker the ability to
    perform site hijacking and cache poisoning.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_222005.81.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpSysInfo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phpsysinfo-2.4.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpsysinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/phpsysinfo", unaffected:make_list("ge 2.4.1"), vulnerable:make_list("lt 2.4.1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpSysInfo");
}
