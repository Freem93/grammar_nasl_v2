#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19326);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_osvdb_id(17397, 17913, 17942, 17964, 17966, 17968, 17969, 17970, 17971, 59834, 77534, 79188, 79395);
  script_xref(name:"GLSA", value:"200507-24");

  script_name(english:"GLSA-200507-24 : Mozilla Suite: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200507-24
(Mozilla Suite: Multiple vulnerabilities)

    The following vulnerabilities were found and fixed in the Mozilla
    Suite:
    'moz_bug_r_a4' and 'shutdown' discovered that the
    Mozilla Suite was improperly cloning base objects (MFSA 2005-56).
    'moz_bug_r_a4' reported that the suite failed to validate XHTML DOM
    nodes properly (MFSA 2005-55).
    Secunia reported that alerts
    and prompts scripts are presented with the generic title [JavaScript
    Application] which could lead to tricking a user (MFSA 2005-54).
    Andreas Sandblad of Secunia reported that top.focus() can be called
    in the context of a child frame even if the framing page comes from a
    different origin and has overridden the focus() routine (MFSA
    2005-52).
    Secunia reported that a frame-injection spoofing bug
    which was fixed in earlier versions, was accidentally bypassed in Mozilla
    Suite 1.7.7 (MFSA 2005-51).
    'shutdown' reported that
    InstallVersion.compareTo() might be exploitable. When it gets an object
    rather than a string, the browser would generally crash with an access
    violation (MFSA 2005-50).
    Matthew Mastracci reported that by
    forcing a page navigation immediately after calling the install method
    can end up running in the context of the new page selected by the
    attacker (MFSA 2005-48).
    'moz_bug_r_a4' reported that XBL
    scripts run even when JavaScript is disabled (MFSA 2005-46).
    Omar Khan, Jochen, 'shutdown' and Matthew Mastracci reported that the
    Mozilla Suite incorrectly distinguished between true events like mouse
    clicks or keystrokes and synthetic events generated by a web content
    (MFSA 2005-45).
  
Impact :

    A remote attacker could craft malicious web pages that would
    leverage these issues to inject and execute arbitrary JavaScript code
    with elevated privileges, steal cookies or other information from web
    pages, or spoof content.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f20085f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.10'
    All Mozilla Suite binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.10'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
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

if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.10"), vulnerable:make_list("lt 1.7.10"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.10"), vulnerable:make_list("lt 1.7.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite");
}
