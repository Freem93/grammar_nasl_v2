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
  script_id(68949);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/10/28 10:42:46 $");

  script_cve_id("CVE-2012-1942", "CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0798", "CVE-2013-0799", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1672", "CVE-2013-1673", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1697");

  script_name(english:"SuSE 11.3 Security Update : Mozilla Firefox (SAT Patch Number 8001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 17.0.7 ESR version, which
fixes bugs and security fixes.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-49)

    Gary Kwong, Jesse Ruderman, and Andrew McCreight
    reported memory safety problems and crashes that affect
    Firefox ESR 17, and Firefox 21. (CVE-2013-1682)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team used the Address Sanitizer
    tool to discover a series of use-after-free problems
    rated critical as security issues in shipped software.
    Some of these issues are potentially exploitable,
    allowing for remote code execution. We would also like
    to thank Abhishek for reporting additional
    use-after-free and buffer overflow flaws in code
    introduced during Firefox development. These were fixed
    before general release. (MFSA 2013-50)

  - Heap-use-after-free in
    mozilla::dom::HTMLMediaElement::LookupMediaElementURITab
    le. (CVE-2013-1684)

  - Heap-use-after-free in nsIDocument::GetRootElement.
    (CVE-2013-1685)

  - Heap-use-after-free in mozilla::ResetDir.
    (CVE-2013-1686)

  - Security researcher Mariusz Mlynski reported that it is
    possible to compile a user-defined function in the XBL
    scope of a specific element and then trigger an event
    within this scope to run code. In some circumstances,
    when this code is run, it can access content protected
    by System Only Wrappers (SOW) and chrome-privileged
    pages. This could potentially lead to arbitrary code
    execution. Additionally, Chrome Object Wrappers (COW)
    can be bypassed by web content to access privileged
    methods, leading to a cross-site scripting (XSS) attack
    from privileged pages. (MFSA 2013-51 / CVE-2013-1687)

  - Security researcher Nils reported that specially crafted
    web content using the onreadystatechange event and
    reloading of pages could sometimes cause a crash when
    unmapped memory is executed. This crash is potentially
    exploitable. (MFSA 2013-53 / CVE-2013-1690)

  - Security researcher Johnathan Kuskos reported that
    Firefox is sending data in the body of XMLHttpRequest
    (XHR) HEAD requests, which goes against the XHR
    specification. This can potentially be used for
    Cross-Site Request Forgery (CSRF) attacks against sites
    which do not distinguish between HEAD and POST requests.
    (MFSA 2013-54 / CVE-2013-1692)

  - Security researcher Paul Stone of Context Information
    Security discovered that timing differences in the
    processing of SVG format images with filters could allow
    for pixel values to be read. This could potentially
    allow for text values to be read across domains, leading
    to information disclosure. (MFSA 2013-55 /
    CVE-2013-1693)

  - Mozilla security researcher moz_bug_r_a4 reported that
    XrayWrappers can be bypassed to call content-defined
    toString and valueOf methods through DefaultValue. This
    can lead to unexpected behavior when privileged code
    acts on the incorrect values. (MFSA 2013-59 /
    CVE-2013-1697)

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-30)

    Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian
    Holler, Milan Sreckovic, and Joe Drew reported memory
    safety problems and crashes that affect Firefox ESR 17,
    and Firefox 19. (CVE-2013-0788)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team used the Address Sanitizer
    tool to discover an out-of-bounds write in Cairo
    graphics library. When certain values are passed to it
    during rendering, Cairo attempts to use negative
    boundaries or sizes for boxes, leading to a potentially
    exploitable crash in some instances. (MFSA 2013-31 /
    CVE-2013-0800)

  - Security researcher Frederic Hoguin discovered that the
    Mozilla Maintenance Service on Windows was vulnerable to
    a buffer overflow. This system is used to update
    software without invoking the User Account Control (UAC)
    prompt. The Mozilla Maintenance Service is configured to
    allow unprivileged users to start it with arbitrary
    arguments. By manipulating the data passed in these
    arguments, an attacker can execute arbitrary code with
    the system privileges used by the service. This issue
    requires local file system access to be exploitable.
    (MFSA 2013-32 / CVE-2013-0799)

  - Security researcher Ash reported an issue with the
    Mozilla Updater. The Mozilla Updater can be made to load
    a malicious local DLL file in a privileged context
    through either the Mozilla Maintenance Service or
    independently on systems that do not use the service.
    This occurs when the DLL file is placed in a specific
    location on the local system before the Mozilla Updater
    is run. Local file system access is necessary in order
    for this issue to be exploitable. (MFSA 2013-34 /
    CVE-2013-0797)

  - Security researcher miaubiz used the Address Sanitizer
    tool to discover a crash in WebGL rendering when memory
    is freed that has not previously been allocated. This
    issue only affects Linux users who have Intel Mesa
    graphics drivers. The resulting crash could be
    potentially exploitable. (MFSA 2013-35 / CVE-2013-0796)

  - Security researcher Cody Crews reported a mechanism to
    use the cloneNode method to bypass System Only Wrappers
    (SOW) and clone a protected node. This allows violation
    of the browser's same origin policy and could also lead
    to privilege escalation and the execution of arbitrary
    code. (MFSA 2013-36 / CVE-2013-0795)

  - Security researcher shutdown reported a method for
    removing the origin indication on tab-modal dialog boxes
    in combination with browser navigation. This could allow
    an attacker's dialog to overlay a page and show another
    site's content. This can be used for phishing by
    allowing users to enter data into a modal prompt dialog
    on an attacking, site while appearing to be from the
    displayed site. (MFSA 2013-37 / CVE-2013-0794)

  - Security researcher Mariusz Mlynski reported a method to
    use browser navigations through history to load an
    arbitrary website with that page's baseURI property
    pointing to another site instead of the seemingly loaded
    one. The user will continue to see the incorrect site in
    the addressbar of the browser. This allows for a
    cross-site scripting (XSS) attack or the theft of data
    through a phishing attack. (MFSA 2013-38 /
    CVE-2013-0793)

  - Mozilla community member Tobias Schula reported that if
    gfx.color_management.enablev4 preference is enabled
    manually in about:config, some grayscale PNG images will
    be rendered incorrectly and cause memory corruption
    during PNG decoding when certain color profiles are in
    use. A crafted PNG image could use this flaw to leak
    data through rendered images drawing from random memory.
    By default, this preference is not enabled. (MFSA
    2013-39 / CVE-2013-0792)

  - Mozilla community member Ambroz Bizjak reported an
    out-of-bounds array read in the CERT_DecodeCertPackage
    function of the Network Security Services (NSS) libary
    when decoding a certificate. When this occurs, it will
    lead to memory corruption and a non-exploitable crash.
    (MFSA 2013-40 / CVE-2013-0791)

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-41)

    References

  - Christoph Diehl, Christian Holler, Jesse Ruderman,
    Timothy Nikkel, and Jeff Walden reported memory safety
    problems and crashes that affect Firefox ESR 17, and
    Firefox 20.

  - Bob Clary, Ben Turner, Benoit Jacob, Bobby Holley,
    Christoph Diehl, Christian Holler, Andrew McCreight,
    Gary Kwong, Jason Orendorff, Jesse Ruderman, Matt
    Wobensmith, and Mats Palmgren reported memory safety
    problems and crashes that affect Firefox 20.

  - Security researcher Cody Crews reported a method to call
    a content level constructor that allows for this
    constructor to have chrome privileged access. This
    affects chrome object wrappers (COW) and allows for
    write actions on objects when only read actions should
    be allowed. This can lead to cross-site scripting (XSS)
    attacks. (MFSA 2013-42 / CVE-2013-1670)

  - Mozilla security researcher moz_bug_r_a4 reported a
    mechanism to exploit the control when set to the file
    type in order to get the full path. This can lead to
    information leakage and could be combined with other
    exploits to target attacks on the local file system.
    (MFSA 2013-43 / CVE-2013-1671)

  - Security researcher Seb Patane reported an issue with
    the Mozilla Maintenance Service on Windows. This issue
    allows unprivileged users to local privilege escalation
    through the system privileges used by the service when
    interacting with local malicious software. This allows
    the user to bypass integrity checks leading to local
    privilege escalation. Local file system access is
    necessary in order for this issue to be exploitable and
    it cannot be triggered through web content. (MFSA
    2013-44 / CVE-2013-1672)

  - Security researcher Robert Kugler discovered that in
    some instances the Mozilla Maintenance Service on
    Windows will be vulnerable to some previously fixed
    privilege escalation attacks that allowed for local
    privilege escalation. This was caused by the Mozilla
    Updater not updating Windows Registry entries for the
    Mozilla Maintenance Service, which fixed the earlier
    issues present if Firefox 12 had been installed. New
    installations of Firefox after version 12 are not
    affected by this issue. Local file system access is
    necessary in order for this issue to be exploitable and
    it cannot be triggered through web content. References:
    - old MozillaMaintenance Service registry entry not
    updated leading to Trusted Path Privilege Escalation
    (CVE-2013-1673) - Possible Arbitrary Code Execution by
    Update Service. (CVE-2012-1942). (MFSA 2013-45)

  - Security researcher Nils reported a use-after-free when
    resizing video while playing. This could allow for
    arbitrary code execution. (MFSA 2013-46 / CVE-2013-1674)

  - Mozilla community member Ms2ger discovered that some
    DOMSVGZoomEvent functions are used without being
    properly initialized, causing uninitialized memory to be
    used when they are called by web content. This could
    lead to a information leakage to sites depending on the
    contents of this uninitialized memory. (MFSA 2013-47 /
    CVE-2013-1675)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team used the Address Sanitizer
    tool to discover a series of use-after-free, out of
    bounds read, and invalid write problems rated as
    moderate to critical as security issues in shipped
    software. Some of these issues are potentially
    exploitable, allowing for remote code execution. We
    would also like to thank Abhishek for reporting
    additional use-after-free flaws in dir=auto code
    introduced during Firefox development. These were fixed
    before general release. (MFSA 2013-48)

    References

  - Out of Bounds Read in SelectionIterator::GetNextSegment.
    (CVE-2013-1676)

  - Out-of-bound read in gfxSkipCharsIterator::SetOffsets
    (CVE-2013-1677))

  - Invalid write in _cairo_xlib_surface_add_glyph.
    (CVE-2013-1678)

  - Heap-use-after-free in
    mozilla::plugins::child::_geturlnotify. (CVE-2013-1679)

  - Heap-use-after-free in nsFrameList::FirstChild.
    (CVE-2013-1680)

  - Heap-use-after-free in
    nsContentUtils::RemoveScriptBlocker. (CVE-2013-1681)

  - CVE-2012-1942

  - CVE-2013-0788

  - CVE-2013-0791

  - CVE-2013-0792

  - CVE-2013-0793

  - CVE-2013-0794

  - CVE-2013-0795

  - CVE-2013-0796

  - CVE-2013-0797

  - CVE-2013-0798

  - CVE-2013-0799

  - CVE-2013-0800

  - CVE-2013-0801

  - CVE-2013-1669

  - CVE-2013-1670

  - CVE-2013-1671

  - CVE-2013-1672

  - CVE-2013-1673

  - CVE-2013-1674

  - CVE-2013-1675

  - CVE-2013-1676

  - CVE-2013-1677

  - CVE-2013-1678

  - CVE-2013-1679

  - CVE-2013-1680

  - CVE-2013-1681

  - CVE-2013-1682

  - CVE-2013-1684

  - CVE-2013-1685

  - CVE-2013-1686

  - CVE-2013-1687

  - CVE-2013-1690

  - CVE-2013-1692

  - CVE-2013-1693

  - CVE-2013-1697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1942.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0791.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0793.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0795.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1671.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1674.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1675.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1676.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1678.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1679.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1680.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1681.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1682.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1684.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1685.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1686.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1693.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1697.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox onreadystatechange Event DocumentViewerImpl Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-17.0.7esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-17.0.7esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-17.0.7esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.7esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-17.0.7esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-branding-SLED-7-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-17.0.7esr-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
