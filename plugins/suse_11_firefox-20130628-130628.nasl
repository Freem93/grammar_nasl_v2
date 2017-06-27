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
  script_id(67195);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/10/28 10:42:46 $");

  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1697");

  script_name(english:"SuSE 11.2 Security Update : Mozilla Firefox (SAT Patch Number 7976)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 17.0.7 ESR version, fixing
bugs and security fixes.

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
    CVE-2013-1697)"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825935"
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
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7976.");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/06");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-17.0.7esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.6.9.31")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-17.0.7esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-17.0.7esr-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.6.9.31")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.7esr-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-17.0.7esr-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-branding-SLED-7-0.6.9.31")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-17.0.7esr-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
