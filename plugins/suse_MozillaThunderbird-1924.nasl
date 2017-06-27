#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-1924.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27125);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/16 19:47:29 $");

  script_cve_id("CVE-2006-3113", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811");

  script_name(english:"openSUSE 10 Security Update : MozillaThunderbird (MozillaThunderbird-1924)");
  script_summary(english:"Check for the MozillaThunderbird-1924 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update brings Mozilla Thunderbird to version 1.5.0.6.

Note that on SUSE Linux 9.2, 9.3 and 10.0 this is a major version
upgrade.

More Details can be found on this page:
http://www.mozilla.org/projects/security/known-vulnerabilities.html

It includes fixes to the following security problems :

  - CVE-2006-3801/MFSA 2006-44: Code execution through
    deleted frame reference

    Thilo Girmann discovered that in certain circumstances a
    JavaScript reference to a frame or window was not
    properly cleared when the referenced content went away,
    and he demonstrated that this pointer to a deleted
    object could be used to execute native code supplied by
    the attacker.

  - CVE-2006-3113/MFSA 2006-46: Memory corruption with
    simultaneous events

    Secunia Research has discovered a vulnerability in
    Mozilla Firefox 1.5 branch, which can be exploited by
    malicious people to compromise a user's system.

    The vulnerability is caused due to an memory corruption
    error within the handling of simultaneously happening
    XPCOM events, which leads to use of a deleted timer
    object. This generally results in a crash but
    potentially could be exploited to execute arbitrary code
    on a user's system when a malicious website is visited.

  - CVE-2006-3802/MFSA 2006-47: Native DOM methods can be
    hijacked across domains

    A malicious page can hijack native DOM methods on a
    document object in another domain, which will run the
    attacker's script when called by the victim page. This
    could be used to steal login cookies, password, or other
    sensitive data on the target page, or to perform actions
    on behalf of a logged-in user.

    Access checks on all other properties and document nodes
    are performed correctly. This cross-site scripting (XSS)
    attack is limited to pages which use standard DOM
    methods of the top-level document object, such as
    document.getElementById(). This includes many popular
    sites, especially the newer ones that offer rich
    interaction to the user.

  - CVE-2006-3803/MFSA 2006-48: JavaScript new Function race
    condition

    H. D. Moore reported a testcase that was able to trigger
    a race condition where JavaScript garbage collection
    deleted a temporary variable still being used in the
    creation of a new Function object. The resulting use of
    a deleted object may be potentially exploitable to run
    native code provided by the attacker.

  - CVE-2006-3804/MFSA 2006-49: Heap buffer overwrite on
    malformed VCard

    A VCard attachment with a malformed base64 field (such
    as a photo) can trigger a heap buffer overwrite. These
    have proven exploitable in the past, though in this case
    the overwrite is accompanied by an integer underflow
    that would attempt to copy more data than the typical
    machine has, leading to a crash.

  - CVE-2006-3805/CVE-2006-3806/MFSA 2006-50: JavaScript
    engine vulnerabilities

    Continuing our security audit of the JavaScript engine,
    Mozilla developers found and fixed several potential
    vulnerabilities.

    Igor Bukanov and shutdown found additional places where
    an untimely garbage collection could delete a temporary
    object that was in active use (similar to MFSA 2006-01
    and MFSA 2006-10). Some of these may allow an attacker
    to run arbitrary code given the right conditions.

    Georgi Guninski found potential integer overflow issues
    with long strings in the toSource() methods of the
    Object, Array and String objects as well as string
    function arguments.

  - CVE-2006-3807/MFSA 2006-51: Privilege escalation using
    named-functions and redefined 'new Object()'

    moz_bug_r_a4 discovered that named JavaScript functions
    have a parent object created using the standard Object()
    constructor (ECMA-specified behavior) and that this
    constructor can be redefined by script (also
    ECMA-specified behavior). If the Object() constructor is
    changed to return a reference to a privileged object
    with useful properties it is possible to have
    attacker-supplied script excuted with elevated
    privileges by calling the function. This could be used
    to install malware or take other malicious actions.

    Our fix involves calling the internal Object constructor
    which appears to be what other ECMA-compatible
    interpreters do.

  - CVE-2006-3808/MFSA 2006-52: PAC privilege escalation
    using Function.prototype.call

    moz_bug_r_a4 reports that a malicious Proxy AutoConfig
    (PAC) server could serve a PAC script that can execute
    code with elevated privileges by setting the required
    FindProxyForURL function to the eval method on a
    privileged object that leaked into the PAC sandbox. By
    redirecting the victim to a specially crafted URL --
    easily done since the PAC script controls which proxy to
    use -- the URL 'hostname' can be executed as privileged
    script.

    A malicious proxy server can perform spoofing attacks on
    the user so it was already important to use a
    trustworthy PAC server.

  - CVE-2006-3809/MFSA 2006-53: UniversalBrowserRead
    privilege escalation

    shutdown reports that scripts granted the
    UniversalBrowserRead privilege can leverage that into
    the equivalent of the far more powerful
    UniversalXPConnect since they are allowed to 'read' into
    a privileged context. This allows the attacker the
    ability to run scripts with the full privelege of the
    user running the browser, possibly installing malware or
    snooping on private data. This has been fixed so that
    UniversalBrowserRead and UniversalBrowserWrite are
    limited to reading from and writing into only
    normally-privileged browser windows and frames.

  - CVE-2006-3810/MFSA 2006-54: XSS with
    XPCNativeWrapper(window).Function(...)

    shutdown reports that cross-site scripting (XSS) attacks
    could be performed using the construct
    XPCNativeWrapper(window).Function(...), which created a
    function that appeared to belong to the window in
    question even after it had been navigated to the target
    site.

  - CVE-2006-3811/MFSA 2006-55: Crashes with evidence of
    memory corruption

    As part of the Firefox 1.5.0.5 stability and security
    release, developers in the Mozilla community looked for
    and fixed several crash bugs to improve the stability of
    Mozilla clients. Some of these crashes showed evidence
    of memory corruption that we presume could be exploited
    to run arbitrary code with enough effort."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-1.5.0.5-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-translations-1.5.0.5-0.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
