#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22146);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2006-3113", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");
  script_osvdb_id(27558, 27560, 27561, 27562, 27563, 27565, 27566, 27568, 27569, 27570, 27571, 27572, 27573, 27574, 27575, 27576, 27577, 94469, 94470, 94471, 94472, 94473, 94474, 94475);
  script_xref(name:"GLSA", value:"200608-04");

  script_name(english:"GLSA-200608-04 : Mozilla Thunderbird: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200608-04
(Mozilla Thunderbird: Multiple vulnerabilities)

    The following vulnerabilities have been reported:
    Benjamin Smedberg discovered that chrome URLss could be made to
    reference remote files.
    Developers in the Mozilla community
    looked for and fixed several crash bugs to improve the stability of
    Mozilla clients.
    'shutdown' reports that cross-site scripting
    (XSS) attacks could be performed using the construct
    XPCNativeWrapper(window).Function(...), which created a function that
    appeared to belong to the window in question even after it had been
    navigated to the target site.
    'shutdown' reports that scripts
    granting the UniversalBrowserRead privilege can leverage that into the
    equivalent of the far more powerful UniversalXPConnect since they are
    allowed to 'read' into a privileged context.
    'moz_bug_r_a4'
    discovered that Named JavaScript functions have a parent object created
    using the standard Object() constructor (ECMA-specified behavior) and
    that this constructor can be redefined by script (also ECMA-specified
    behavior).
    Igor Bukanov and shutdown found additional places
    where an untimely garbage collection could delete a temporary object
    that was in active use.
    Georgi Guninski found potential
    integer overflow issues with long strings in the toSource() methods of
    the Object, Array and String objects as well as string function
    arguments.
    H. D. Moore reported a testcase that was able to
    trigger a race condition where JavaScript garbage collection deleted a
    temporary variable still being used in the creation of a new Function
    object.
    A malicious page can hijack native DOM methods on a
    document object in another domain, which will run the attacker's script
    when called by the victim page.
    Secunia Research has
    discovered a vulnerability which is caused due to an memory corruption
    error within the handling of simultaneously happening XPCOM events.
    This leads to use of a deleted timer object.
  
Impact :

    A user can be enticed to open specially crafted URLs, visit webpages
    containing malicious JavaScript or execute a specially crafted script.
    These events could lead to the execution of arbitrary code, or the
    installation of malware on the user's computer.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-1.5.0.5'
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-1.5.0.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 1.5.0.5"), vulnerable:make_list("lt 1.5.0.5"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 1.5.0.5"), vulnerable:make_list("lt 1.5.0.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
