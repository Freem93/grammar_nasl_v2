#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29354);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/16 19:47:29 $");

  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");

  script_name(english:"SuSE 10 Security Update : Firefox (ZYPP Patch Number 1960)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update brings Mozilla Firefox to version 1.5.0.6.

More details can be found on:
http://www.mozilla.org/projects/security/known-vulnerabiliti es.html

It includes fixes to the following security problems :

  - Code execution through deleted frame reference.
    (CVE-2006-3801 / MFSA 2006-44)

    Thilo Girmann discovered that in certain circumstances a
    JavaScript reference to a frame or window was not
    properly cleared when the referenced content went away,
    and he demonstrated that this pointer to a deleted
    object could be used to execute native code supplied by
    the attacker.

  - JavaScript navigator Object Vulnerability.
    (CVE-2006-3677 / MFSA 2006-45)

    An anonymous researcher for TippingPoint and the Zero
    Day Initiative showed that when used in a web page Java
    would reference properties of the window.navigator
    object as it started up. If the page replaced the
    navigator object before starting Java then the browser
    would crash in a way that could be exploited to run
    native code supplied by the attacker.

  - Memory corruption with simultaneous events.
    (CVE-2006-3113 / MFSA 2006-46)

    Secunia Research has discovered a vulnerability in
    Mozilla Firefox 1.5 branch, which can be exploited by
    malicious people to compromise a user's system.

    The vulnerability is caused due to an memory corruption
    error within the handling of simultaneously happening
    XPCOM events, which leads to use of a deleted timer
    object. This generally results in a crash but
    potentially could be exploited to execute arbitrary code
    on a user's system when a malicious website is visited.

  - Native DOM methods can be hijacked across domains.
    (CVE-2006-3802 / MFSA 2006-47)

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

  - JavaScript new Function race condition. (CVE-2006-3803 /
    MFSA 2006-48)

    H. D. Moore reported a testcase that was able to trigger
    a race condition where JavaScript garbage collection
    deleted a temporary variable still being used in the
    creation of a new Function object. The resulting use of
    a deleted object may be potentially exploitable to run
    native code provided by the attacker.

  - Heap buffer overwrite on malformed VCard. (CVE-2006-3804
    / MFSA 2006-49)

    A VCard attachment with a malformed base64 field (such
    as a photo) can trigger a heap buffer overwrite. These
    have proven exploitable in the past, though in this case
    the overwrite is accompanied by an integer underflow
    that would attempt to copy more data than the typical
    machine has, leading to a crash.

  - JavaScript engine vulnerabilities. (CVE-2006-3805 /
    CVE-2006-3806 / MFSA 2006-50)

    Continuing our security audit of the JavaScript engine,
    Mozilla developers found and fixed several potential
    vulnerabilities.

    Igor Bukanov and shutdown found additional places where
    an untimely garbage collection could delete a temporary
    object that was in active use (similar to MFSA 2006-01 /
    MFSA 2006-10). Some of these may allow an attacker to
    run arbitrary code given the right conditions.

    Georgi Guninski found potential integer overflow issues
    with long strings in the toSource() methods of the
    Object, Array and String objects as well as string
    function arguments.

  - Privilege escalation using named-functions and redefined
    'new Object()'. (CVE-2006-3807 / MFSA 2006-51)

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

  - PAC privilege escalation using Function.prototype.call.
    (CVE-2006-3808 / MFSA 2006-52)

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

  - UniversalBrowserRead privilege escalation.
    (CVE-2006-3809 / MFSA 2006-53)

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

  - XSS with XPCNativeWrapper(window).Function(...).
    (CVE-2006-3810 / MFSA 2006-54)

    shutdown reports that cross-site scripting (XSS) attacks
    could be performed using the construct
    XPCNativeWrapper(window).Function(...), which created a
    function that appeared to belong to the window in
    question even after it had been navigated to the target
    site.

  - Crashes with evidence of memory corruption.
    (CVE-2006-3811 / MFSA 2006-55)

    As part of the Firefox 1.5.0.5 stability and security
    release, developers in the Mozilla community looked for
    and fixed several crash bugs to improve the stability of
    Mozilla clients. Some of these crashes showed evidence
    of memory corruption that we presume could be exploited
    to run arbitrary code with enough effort.

  - chrome: scheme loading remote content. (CVE-2006-3812 /
    MFSA 2006-56)

    Benjamin Smedberg discovered that chrome URL's could be
    made to reference remote files, which would run scripts
    with full privilege. There is no known way for web
    content to successfully load a chrome: url, but if a
    user could be convinced to do so manually (perhaps by
    copying a link and pasting it into the location bar)
    this could be exploited."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3804.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3811.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3812.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 1960.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-1.5.0.6-1.2")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-translations-1.5.0.6-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-1.5.0.6-1.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-translations-1.5.0.6-1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
