#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18270);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/31 14:21:56 $");

  script_cve_id("CVE-2005-1476", "CVE-2005-1477");
  script_osvdb_id(16185, 16186, 16576, 79345, 79346);
  script_xref(name:"GLSA", value:"200505-11");

  script_name(english:"GLSA-200505-11 : Mozilla Suite, Mozilla Firefox: Remote compromise");
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
"The remote host is affected by the vulnerability described in GLSA-200505-11
(Mozilla Suite, Mozilla Firefox: Remote compromise)

    The Mozilla Suite and Firefox do not properly protect 'IFRAME'
    JavaScript URLs from being executed in context of another URL in the
    history list (CAN-2005-1476). The Mozilla Suite and Firefox also fail
    to verify the 'IconURL' parameter of the 'InstallTrigger.install()'
    function (CAN-2005-1477). Michael Krax and Georgi Guninski discovered
    that it is possible to bypass JavaScript-injection security checks by
    wrapping the javascript: URL within the view-source: or jar:
    pseudo-protocols (MFSA2005-43).
  
Impact :

    A malicious remote attacker could use the 'IFRAME' issue to
    execute arbitrary JavaScript code within the context of another
    website, allowing to steal cookies or other sensitive data. By
    supplying a javascript: URL as the 'IconURL' parameter of the
    'InstallTrigger.Install()' function, a remote attacker could also
    execute arbitrary JavaScript code. Combining both vulnerabilities with
    a website which is allowed to install software or wrapping javascript:
    URLs within the view-source: or jar: pseudo-protocols could possibly
    lead to the execution of arbitrary code with user privileges.
  
Workaround :

    Affected systems can be protected by disabling JavaScript.
    However, we encourage Mozilla Suite or Mozilla Firefox users to upgrade
    to the latest available version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-1.0.4'
    All Mozilla Firefox binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-1.0.4'
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.8'
    All Mozilla Suite binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/07");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 1.0.4"), vulnerable:make_list("lt 1.0.4"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.8"), vulnerable:make_list("lt 1.7.8"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.8"), vulnerable:make_list("lt 1.7.8"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 1.0.4"), vulnerable:make_list("lt 1.0.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite / Mozilla Firefox");
}
