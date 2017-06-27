#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50951);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-2753", "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3131", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169", "CVE-2010-3170", "CVE-2010-3174", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");

  script_name(english:"SuSE 11 / 11.1 Security Update : Mozilla (SAT Patch Numbers 3417 / 3419)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla XULRunner to version 1.9.1.14, fixing
various bugs and security issues.

The following security issues were fixed :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2010-49 / CVE-2010-3169)

  - Security researcher Chris Rohlf of Matasano Security
    reported that the implementation of the HTML frameset
    element contained an integer overflow vulnerability. The
    code responsible for parsing the frameset columns used
    an 8-byte counter for the column numbers, so when a very
    large number of columns was passed in the counter would
    overflow. When this counter was subsequently used to
    allocate memory for the frameset, the memory buffer
    would be too small, potentially resulting in a heap
    buffer overflow and execution of attacker-controlled
    memory. (MFSA 2010-50 / CVE-2010-2765)

  - Security researcher Sergey Glazunov reported a dangling
    pointer vulnerability in the implementation of
    navigator.plugins in which the navigator object could
    retain a pointer to the plugins array even after it had
    been destroyed. An attacker could potentially use this
    issue to crash the browser and run arbitrary code on a
    victim's computer. (MFSA 2010-51 / CVE-2010-2767)

  - Security researcher Haifei Li of FortiGuard Labs
    reported that Firefox could be used to load a malicious
    code library that had been planted on a victim's
    computer. Firefox attempts to load dwmapi.dll upon
    startup as part of its platform detection, so on systems
    that don't have this library, such as Windows XP,
    Firefox will subsequently attempt to load the library
    from the current working directory. An attacker could
    use this vulnerability to trick a user into downloading
    a HTML file and a malicious copy of dwmapi.dll into the
    same directory on their computer and opening the HTML
    file with Firefox, thus causing the malicious code to be
    executed. If the attacker was on the same network as the
    victim, the malicious DLL could also be loaded via a UNC
    path. The attack also requires that Firefox not
    currently be running when it is asked to open the HTML
    file and accompanying DLL. As this is a Windows only
    problem, it does not affect the Linux version. It is
    listed for completeness only. (MFSA 2010-52 /
    CVE-2010-3131)

  - Security researcher wushi of team509 reported a heap
    buffer overflow in code routines responsible for
    transforming text runs. A page could be constructed with
    a bidirectional text run which upon reflow could result
    in an incorrect length being calculated for the run of
    text. When this value is subsequently used to allocate
    memory for the text too small a buffer may be created
    potentially resulting in a buffer overflow and the
    execution of attacker controlled memory. (MFSA 2010-53 /
    CVE-2010-3166)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that there was a
    remaining dangling pointer issue leftover from the fix
    to CVE-2010-2753. Under certain circumstances one of the
    pointers held by a XUL tree selection could be freed and
    then later reused, potentially resulting in the
    execution of attacker-controlled memory. (MFSA 2010-54 /
    CVE-2010-2760)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that XUL objects
    could be manipulated such that the setting of certain
    properties on the object would trigger the removal of
    the tree from the DOM and cause certain sections of
    deleted memory to be accessed. In products based on
    Gecko version 1.9.2 (Firefox 3.6, Thunderbird 3.1) and
    newer this memory has been overwritten by a value that
    will cause an unexploitable crash. In products based on
    Gecko version 1.9.1 (Firefox 3.5, Thunderbird 3.0, and
    SeaMonkey 2.0) and older an attacker could potentially
    use this vulnerability to crash a victim's browser and
    run arbitrary code on their computer. (MFSA 2010-55 /
    CVE-2010-3168)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that the
    implementation of XUL's content view contains a dangling
    pointer vulnerability. One of the content view's methods
    for accessing the internal structure of the tree could
    be manipulated into removing a node prior to accessing
    it, resulting in the accessing of deleted memory. If an
    attacker can control the contents of the deleted memory
    prior to its access they could use this vulnerability to
    run arbitrary code on a victim's machine. (MFSA 2010-56
    / CVE-2010-3167)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that code used to
    normalize a document contained a logical flaw that could
    be leveraged to run arbitrary code. When the
    normalization code ran, a static count of the document's
    child nodes was used in the traversal, so a page could
    be constructed that would remove DOM nodes during this
    normalization which could lead to the accessing of a
    deleted object and potentially the execution of
    attacker-controlled memory. (MFSA 2010-57 /
    CVE-2010-2766)

  - Security researcher Marc Schoenefeld reported that a
    specially crafted font could be applied to a document
    and cause a crash on Mac systems. The crash showed signs
    of memory corruption and presumably could be used by an
    attacker to execute arbitrary code on a victim's
    computer. This issue probably does not affect the Linux
    builds and so is listed for completeness. (MFSA 2010-58
    / CVE-2010-2770)

  - Mozilla developer Blake Kaplan reported that the wrapper
    class XPCSafeJSObjectWrapper (SJOW), a security wrapper
    that allows content-defined objects to be safely
    accessed by privileged code, creates scope chains ending
    in outer objects. Users of SJOWs which expect the scope
    chain to end on an inner object may be handed a chrome
    privileged object which could be leveraged to run
    arbitrary JavaScript with chrome privileges. Michal
    Zalewski's recent contributions helped to identify this
    architectural weakness. (MFSA 2010-59 / CVE-2010-2762)

  - Mozilla security researcher mozbugr_a4 reported that the
    wrapper class XPCSafeJSObjectWrapper (SJOW) on the
    Mozilla 1.9.1 development branch has a logical error in
    its scripted function implementation that allows the
    caller to run the function within the context of another
    site. This is a violation of the same-origin policy and
    could be used to mount an XSS attack. (MFSA 2010-60 /
    CVE-2010-2763)

  - Security researchers David Huang and Collin Jackson of
    Carnegie Mellon University CyLab (Silicon Valley campus)
    reported that the type attribute of an tag can override
    the charset of a framed HTML document, even when the
    document is included across origins. A page could be
    constructed containing such an tag which sets the
    charset of the framed document to UTF-7. This could
    potentially allow an attacker to inject UTF-7 encoded
    JavaScript into a site, bypassing the site's XSS
    filters, and then executing the code using the above
    technique. (MFSA 2010-61 / CVE-2010-2768)

  - Security researcher Paul Stone reported that when an
    HTML selection containing JavaScript is copy-and-pasted
    or dropped onto a document with designMode enabled the
    JavaScript will be executed within the context of the
    site where the code was dropped. A malicious site could
    leverage this issue in an XSS attack by persuading a
    user into taking such an action and in the process
    running malicious JavaScript within the context of
    another site. (MFSA 2010-62 / CVE-2010-2769)

  - Matt Haggard reported that the statusText property of an
    XMLHttpRequest object is readable by the requestor even
    when the request is made across origins. This status
    information reveals the presence of a web server and
    could be used to gather information about servers on
    internal private networks. This issue was also
    independently reported to Mozilla by Nicholas Berthaume.
    (MFSA 2010-63 / CVE-2010-2764)

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. References. (MFSA 2010-64)

    Paul Nickerson, Jesse Ruderman, Olli Pettay, Igor
    Bukanov and Josh Soref reported memory safety problems
    that affected Firefox 3.6 and Firefox 3.5.

  - Memory safety bugs - Firefox 3.6, Firefox 3.5

  - Jesse Ruderman reported a crash which affected Firefox
    3.5 only. (CVE-2010-3176)

  - https://bugzilla.mozilla.org/show_bug.cgi?id=476547

  - CVE-2010-3174

  - Security researcher Alexander Miller reported that
    passing an excessively long string to document.write
    could cause text rendering routines to end up in an
    inconsistent state with sections of stack memory being
    overwritten with the string data. An attacker could use
    this flaw to crash a victim's browser and potentially
    run arbitrary code on their computer. (MFSA 2010-65 /
    CVE-2010-3179)

  - Security researcher Sergey Glazunov reported that it was
    possible to access the locationbar property of a window
    object after it had been closed. Since the closed
    window's memory could have been subsequently reused by
    the system it was possible that an attempt to access the
    locationbar property could result in the execution of
    attacker-controlled memory. (MFSA 2010-66 /
    CVE-2010-3180)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that when
    window.__lookupGetter__ is called with no arguments the
    code assumes the top JavaScript stack value is a
    property name. Since there were no arguments passed into
    the function, the top value could represent
    uninitialized memory or a pointer to a previously freed
    JavaScript object. Under such circumstances the value is
    passed to another subroutine which calls through the
    dangling pointer, potentially executing
    attacker-controlled memory. (MFSA 2010-67 /
    CVE-2010-3183)

  - Google security researcher Robert Swiecki reported that
    functions used by the Gopher parser to convert text to
    HTML tags could be exploited to turn text into
    executable JavaScript. If an attacker could create a
    file or directory on a Gopher server with the encoded
    script as part of its name the script would then run in
    a victim's browser within the context of the site. (MFSA
    2010-68 / CVE-2010-3177)

  - Security researcher Eduardo Vela Nava reported that if a
    web page opened a new window and used a javascript: URL
    to make a modal call, such as alert(), then subsequently
    navigated the page to a different domain, once the modal
    call returned the opener of the window could get access
    to objects in the navigated window. This is a violation
    of the same-origin policy and could be used by an
    attacker to steal information from another web site.
    (MFSA 2010-69 / CVE-2010-3178)

  - Security researcher Richard Moore reported that when an
    SSL certificate was created with a common name
    containing a wildcard followed by a partial IP address a
    valid SSL connection could be established with a server
    whose IP address matched the wildcard range by browsing
    directly to the IP address. It is extremely unlikely
    that such a certificate would be issued by a Certificate
    Authority. (MFSA 2010-70 / CVE-2010-3170)

  - Dmitri Gribenko reported that the script used to launch
    Mozilla applications on Linux was effectively including
    the current working directory in the LD_LIBRARY_PATH
    environment variable. If an attacker was able to place
    into the current working directory a malicious shared
    library with the same name as a library that the
    bootstrapping script depends on the attacker could have
    their library loaded instead of the legitimate library.
    (MFSA 2010-71 / CVE-2010-3182)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-57.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-70.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2762.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2764.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2765.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2768.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3183.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3417 / 3419 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
