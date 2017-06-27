#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18090);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1159", "CVE-2005-1160");
  script_osvdb_id(15241, 15682, 15683, 15684, 15685, 15686, 15687, 15688, 15689, 15690);
  script_xref(name:"GLSA", value:"200504-18");

  script_name(english:"GLSA-200504-18 : Mozilla Firefox, Mozilla Suite: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200504-18
(Mozilla Firefox, Mozilla Suite: Multiple vulnerabilities)

    The following vulnerabilities were found and fixed in the Mozilla Suite
    and Mozilla Firefox:
    Vladimir V. Perepelitsa reported a memory disclosure bug in
    JavaScript's regular expression string replacement when using an
    anonymous function as the replacement argument (CAN-2005-0989).
    moz_bug_r_a4 discovered that Chrome UI code was overly trusting DOM
    nodes from the content window, allowing privilege escalation via DOM
    property overrides.
    Michael Krax reported a possibility to run JavaScript code with
    elevated privileges through the use of javascript: favicons.
    Michael Krax also discovered that malicious Search plugins could
    run JavaScript in the context of the displayed page or stealthily
    replace existing search plugins.
    shutdown discovered a technique to pollute the global scope of a
    window in a way that persists from page to page.
    Doron Rosenberg discovered a possibility to run JavaScript with
    elevated privileges when the user asks to 'Show' a blocked popup that
    contains a JavaScript URL.
    Finally, Georgi Guninski reported missing Install object instance
    checks in the native implementations of XPInstall-related JavaScript
    objects.
    The following Firefox-specific vulnerabilities have also been
    discovered:
    Kohei Yoshino discovered a new way to abuse the sidebar panel to
    execute JavaScript with elevated privileges.
    Omar Khan reported that the Plugin Finder Service can be tricked to
    open javascript: URLs with elevated privileges.
  
Impact :

    The various JavaScript execution with elevated privileges issues can be
    exploited by a remote attacker to install malicious code or steal data.
    The memory disclosure issue can be used to reveal potentially sensitive
    information. Finally, the cache pollution issue and search plugin abuse
    can be leveraged in cross-site-scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-1.0.3'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-1.0.3'
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.7'
    All Mozilla Suite binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 1.0.3"), vulnerable:make_list("lt 1.0.3"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.7"), vulnerable:make_list("lt 1.7.7"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.7"), vulnerable:make_list("lt 1.7.7"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 1.0.3"), vulnerable:make_list("lt 1.0.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox / Mozilla Suite");
}
