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
  script_id(65175);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");

  script_name(english:"SuSE 11.2 Security Update : Mozilla Firefox (SAT Patch Number 7447)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 17.0.3ESR release.

Important: due to compatibility issues, the Beagle plug-in for
MozillaFirefox is temporarily disabled by this update.

Besides the major version update from the 10ESR stable release line to
the 17ESR stable release line, this update brings critical security
and bugfixes :

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team used the Address Sanitizer
    tool to discover a series of use-after-free, out of
    bounds read, and buffer overflow problems rated as low
    to critical security issues in shipped software. Some of
    these issues are potentially exploitable, allowing for
    remote code execution. We would also like to thank
    Abhishek for reporting four additional use-after-free
    and out of bounds write flaws introduced during Firefox
    development that were fixed before general release.
    (MFSA 2013-28)

  - The following issues have been fixed in Firefox 19 and
    ESR 17.0.3 :

  - Heap-use-after-free in
    nsOverflowContinuationTracker::Finish, with
    -moz-columns. (CVE-2013-0780)

  - Heap-buffer-overflow WRITE in
    nsSaveAsCharset::DoCharsetConversion. (CVE-2013-0782)

  - Google security researcher Michal Zalewski reported an
    issue where the browser displayed the content of a
    proxy's 407 response if a user canceled the proxy's
    authentication prompt. In this circumstance, the
    addressbar will continue to show the requested site's
    address, including HTTPS addresses that appear to be
    secure. This spoofing of addresses can be used for
    phishing attacks by fooling users into entering
    credentials, for example. (MFSA 2013-27 / CVE-2013-0776)

  - Security researcher Nils reported a use-after-free in
    nsImageLoadingContent when content script is executed.
    This could allow for arbitrary code execution. (MFSA
    2013-26 / CVE-2013-0775)

  - Mozilla security researcher Frederik Braun discovered
    that since Firefox 15 the file system location of the
    active browser profile was available to JavaScript
    workers. While not dangerous by itself, this could
    potentially be combined with other vulnerabilities to
    target the profile in an attack. (MFSA 2013-25 /
    CVE-2013-0774)

  - Mozilla developer Bobby Holley discovered that it was
    possible to bypass some protections in Chrome Object
    Wrappers (COW) and System Only Wrappers (SOW), making
    their prototypes mutable by web content. This could be
    used leak information from chrome objects and possibly
    allow for arbitrary code execution. (MFSA 2013-24 /
    CVE-2013-0773)

  - Mozilla developer Boris Zbarsky reported that in some
    circumstances a wrapped WebIDL object can be wrapped
    multiple times, overwriting the existing wrapped state.
    This could lead to an exploitable condition in rare
    cases. (MFSA 2013-23 / CVE-2013-0765)

  - Using the Address Sanitizer tool, security researcher
    Atte Kettunen from OUSPG found an out-of-bounds read
    while rendering GIF format images. This could cause a
    non-exploitable crash and could also attempt to render
    normally inaccesible data as part of the image. (MFSA
    2013-22 / CVE-2013-0772)

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-21)

    Olli Pettay, Christoph Diehl, Gary Kwong, Jesse
    Ruderman, Andrew McCreight, Joe Drew, and Wayne Mery
    reported memory safety problems and crashes that affect
    Firefox ESR 17, and Firefox 18.

  - Memory safety bugs fixed in Firefox ESR 17.0.3, and
    Firefox 19. (CVE-2013-0783)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0765.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0783.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7447.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mhtml-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.6.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"beagle-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"beagle-evolution-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"beagle-firefox-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"beagle-gui-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"beagle-lang-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mhtml-firefox-0.5-1.47.51.5")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.6.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"beagle-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"beagle-evolution-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"beagle-firefox-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"beagle-gui-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"beagle-lang-0.3.8-56.51.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mhtml-firefox-0.5-1.47.51.5")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-tools-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-branding-SLED-7-0.6.9.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-17.0.3esr-0.4.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libfreebl3-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nspr-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-tools-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libfreebl3-32bit-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nss-32bit-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14.2-0.4.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.5-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.2-0.4.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
