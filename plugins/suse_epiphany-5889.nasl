#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41504);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512");

  script_name(english:"SuSE 10 Security Update : Epiphany (ZYPP Patch Number 5889)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla XULRunner 1.8.1 engine received backports for security
problems in 1.9.0.5.

The following security issues were fixed :

  - Mozilla security researcher moz_bug_r_a4 reported that
    an XBL binding, when attached to an unloaded document,
    can be used to violate the same-origin policy and
    execute arbitrary JavaScript within the context of a
    different website. moz_bug_r_a4 also reported two
    vulnerabilities by which page content can pollute
    XPCNativeWrappers and run arbitary JavaScript with
    chrome priviliges. Thunderbird shares the browser engine
    with Firefox and could be vulnerable if JavaScript were
    to be enabled in mail. This is not the default setting
    and we strongly discourage users from running JavaScript
    in mail. Workaround Disable JavaScript until a version
    containing these fixes can be installed. (MFSA 2008-68 /
    CVE-2008-5512 / CVE-2008-5511)

  - Kojima Hajime reported that unlike literal null
    characters which were handled correctly, the escaped
    form '\0' was ignored by the CSS parser and treated as
    if it was not present in the CSS input string. This
    issue could potentially be used to bypass script
    sanitization routines in web applications. The severity
    of this issue was determined to be low. (MFSA 2008-67 /
    CVE-2008-5510)

  - Perl developer Chip Salzenberg reported that certain
    control characters, when placed at the beginning of a
    URL, would lead to incorrect parsing resulting in a
    malformed URL being output by the parser. IBM
    researchers Justin Schuh, Tom Cross, and Peter William
    also reported a related symptom as part of their
    research that resulted in MFSA 2008-37. There was no
    direct security impact from this issue and its effect
    was limited to the improper rendering of hyperlinks
    containing specific characters. The severity of this
    issue was determined to be low. (MFSA 2008-66 /
    CVE-2008-5508)

  - Google security researcher Chris Evans reported that a
    website could access a limited amount of data from a
    different domain by loading a same-domain JavaScript URL
    which redirects to an off-domain target resource
    containing data which is not parsable as JavaScript.
    Upon attempting to load the data as JavaScript a syntax
    error is generated that can reveal some of the file
    context via the window.onerror DOM API. This issue could
    be used by a malicious website to steal private data
    from users who are authenticated on the redirected
    website. How much data could be at risk would depend on
    the format of the data and how the JavaScript parser
    attempts to interpret it. For most files the amount of
    data that can be recovered would be limited to the first
    word or two. Some data files might allow deeper probing
    with repeated loads. Thunderbird shares the browser
    engine with Firefox and could be vulnerable if
    JavaScript were to be enabled in mail. This is not the
    default setting and we strongly discourage users from
    running JavaScript in mail. Workaround Disable
    JavaScript until a version containing these fixes can be
    installed. (MFSA 2008-65 / CVE-2008-5507)

  - Marius Schilder of Google Security reported that when a
    XMLHttpRequest is made to a same-origin resource which
    302 redirects to a resource in a different domain, the
    response from the cross-domain resource is readable by
    the site issuing the XHR. Cookies marked HttpOnly were
    not readable, but other potentially sensitive data could
    be revealed in the XHR response including URL parameters
    and content in the response body. Thunderbird shares the
    browser engine with Firefox and could be vulnerable if
    JavaScript were to be enabled in mail. This is not the
    default setting and we strongly discourage users from
    running JavaScript in mail. Workaround Disable
    JavaScript until a version containing these fixes can be
    installed. (MFSA 2008-64 / CVE-2008-5506)

  - Mozilla developer Boris Zbarsky reported that XBL
    bindings could be used to read data from other domains,
    a violation of the same-origin policy. The severity of
    this issue was determined to be moderate due to several
    mitigating factors: The target document requires a
    <bindingsi> element in the XBL namespace in order to be
    read. The reader of the data needs to know the id
    attribute of the binding being read in advance. It is
    unlikely that web services will expose private data in
    the manner described above. Firefox 3 is not affected by
    this issue. Thunderbird shares the browser engine with
    Firefox and could be vulnerable if JavaScript were to be
    enabled in mail. This is not the default setting and we
    strongly discourage users from running JavaScript in
    mail. Workaround Products built from the Mozilla 1.9.0
    branch and later, Firefox 3 for example, are not
    affected by this issue. Upgrading to one of these
    products is a reliable workaround for this particular
    issue and it is also Mozilla's recommendation that the
    most current version of any Mozilla product be used.
    Alternatively, you can disable JavaScript until a
    version containing these fixes can be installed. (MFSA
    2008-61 / CVE-2008-5503)

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. Thunderbird shares the browser engine with Firefox
    and could be vulnerable if JavaScript were to be enabled
    in mail. This is not the default setting and we strongly
    discourage users from running JavaScript in mail.
    Without further investigation we cannot rule out the
    possibility that for some of these an attacker might be
    able to prepare memory for exploitation through some
    means other than JavaScript such as large images.
    Workaround Disable JavaScript until a version containing
    these fixes can be installed. (MFSA 2008-60 /
    CVE-2008-5500)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5507.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5512.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5889.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"epiphany-1.8.5-14.7")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"gecko-sdk-1.8.0.14eol-0.12")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner-1.8.0.14eol-0.12")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.9")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner-1.8.0.14eol-0.12")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
