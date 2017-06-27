#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65866);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/04/24 13:06:47 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0790", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0798", "CVE-2013-0799", "CVE-2013-0800");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 8537)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox has been updated to the 17.0.5ESR release fixing bugs
and security issues.

Also Mozilla NSS has been updated to version 3.14.3 and Mozilla NSPR
to 4.9.6.

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

    Andrew McCreight, Randell Jesup, Gary Kwong, Jesse
    Ruderman, Christian Holler, and Mats Palmgren reported
    memory safety problems and crashes that affect Firefox
    19. (CVE-2013-0789)

    Jim Chen reported a memory safety problem that affects
    Firefox for Android 19. (CVE-2013-0790)

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

  - Security researcher Shuichiro Suzuki of the
    Fourteenforty Research Institute reported the app_tmp
    directory is set to be world readable and writeable by
    Firefox for Android. This potentially allows for
    third-party applications to replace or alter Firefox
    add-ons when downloaded because they are temporarily
    stored in the app_tmp directory before installation.
    (MFSA 2013-33 / CVE-2013-0798)

    This vulnerability only affects Firefox for Android.

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

  - / CVE-2013-079: Security researcher Mariusz Mlynski
    reported a method to use browser navigations through
    history to load an arbitrary website with that page's
    baseURI property pointing to another site instead of the
    seemingly loaded one. The user will continue to see the
    incorrect site in the addressbar of the browser. This
    allows for a cross-site scripting (XSS) attack or the
    theft of data through a phishing attack. (MFSA 2013-38)

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
    (MFSA 2013-40 / CVE-2013-0791)"
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
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-33.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-0788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0790.html"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8537.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-17.0.5esr-0.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-branding-SLED-7-0.10.11")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"MozillaFirefox-translations-17.0.5esr-0.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nspr-devel-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-devel-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-tools-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-17.0.5esr-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-branding-SLED-7-0.10.11")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"MozillaFirefox-translations-17.0.5esr-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nspr-devel-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-devel-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-tools-3.14.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
