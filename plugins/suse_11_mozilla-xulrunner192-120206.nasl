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
  script_id(57886);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");

  script_name(english:"SuSE 11.1 Security Update : Mozilla XULrunner (SAT Patch Number 5764)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XULrunner was updated to 1.9.2.26 security update, fixing
security issues and bugs. The following security bugs have been 
fixed :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-01)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.
    References

  - Jesse Ruderman and Bob Clary reported memory safety
    problems that were fixed in both Firefox 10 and Firefox
    3.6.26. (CVE-2012-0442)

  - For historical reasons Firefox has been generous in its
    interpretation of web addresses containing square
    brackets around the host. If this host was not a valid
    IPv6 literal address, Firefox attempted to interpret the
    host as a regular domain name. Gregory Fleischer
    reported that requests made using IPv6 syntax using
    XMLHttpRequest objects through a proxy may generate
    errors depending on proxy configuration for IPv6. The
    resulting error messages from the proxy may disclose
    sensitive data because Same-Origin Policy (SOP) will
    allow the XMLHttpRequest object to read these error
    messages, allowing user privacy to be eroded. Firefox
    now enforces RFC 3986 IPv6 literal syntax and that may
    break links written using the non-standard Firefox-only
    forms that were previously accepted. (MFSA 2012-02 /
    CVE-2011-3670)

    This was fixed previously for Firefox 7.0, Thunderbird
    7.0, and SeaMonkey 2.4 but only fixed in Firefox 3.6.26
    and Thunderbird 3.1.18 during 2012.

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that removed child
    nodes of nsDOMAttribute can be accessed under certain
    circumstances because of a premature notification of
    AttributeChildRemoved. This use-after-free of the child
    nodes could possibly allow for for remote code
    execution. (MFSA 2012-04 / CVE-2011-3659)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative the possibility of
    memory corruption during the decoding of Ogg Vorbis
    files. This can cause a crash during decoding and has
    the potential for remote code execution. (MFSA 2012-07 /
    CVE-2012-0444)

  - Security researchers Nicolas Gregoire and Aki Helin
    independently reported that when processing a malformed
    embedded XSLT stylesheet, Firefox can crash due to a
    memory corruption. While there is no evidence that this
    is directly exploitable, there is a possibility of
    remote code execution. (MFSA 2012-08 / CVE-2012-0449)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3659.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0449.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5764.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-gnome-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-translations-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-gnome-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-translations-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner192-32bit-1.9.2.26-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.26-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
