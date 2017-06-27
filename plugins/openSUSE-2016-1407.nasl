#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1407.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95590);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5293", "CVE-2016-5294", "CVE-2016-5295", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-5298", "CVE-2016-5299", "CVE-2016-9061", "CVE-2016-9062", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9065", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9072", "CVE-2016-9073", "CVE-2016-9074", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077", "CVE-2016-9078", "CVE-2016-9079");

  script_name(english:"openSUSE Security Update : Mozilla Firefox / Thunderbird and NSS (openSUSE-2016-1407)");
  script_summary(english:"Check for the openSUSE-2016-1407 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Mozilla Firefox 50.0.2, Thunderbird 45.5.1 and NSS
3.16.2 fixes a number of security issues.

The following vulnerabilities were fixed in Mozilla Firefox (MFSA
2016-89) :

  - CVE-2016-5296: Heap-buffer-overflow WRITE in
    rasterize_edges_1 (bmo#1292443)

  - CVE-2016-5292: URL parsing causes crash (bmo#1288482)

  - CVE-2016-5297: Incorrect argument length checking in
    JavaScript (bmo#1303678)

  - CVE-2016-9064: Addons update must verify IDs match
    between current and new versions (bmo#1303418)

  - CVE-2016-9066: Integer overflow leading to a buffer
    overflow in nsScriptLoadHandler (bmo#1299686)

  - CVE-2016-9067: heap-use-after-free in
    nsINode::ReplaceOrInsertBefore (bmo#1301777, bmo#1308922
    (CVE-2016-9069))

  - CVE-2016-9068: heap-use-after-free in nsRefreshDriver
    (bmo#1302973)

  - CVE-2016-9075: WebExtensions can access the
    mozAddonManager API and use it to gain elevated
    privileges (bmo#1295324)

  - CVE-2016-9077: Canvas filters allow feDisplacementMaps
    to be applied to cross-origin images, allowing timing
    attacks on them (bmo#1298552)

  - CVE-2016-5291: Same-origin policy violation using local
    HTML file and saved shortcut file (bmo#1292159)

  - CVE-2016-9070: Sidebar bookmark can have reference to
    chrome window (bmo#1281071)

  - CVE-2016-9073: windows.create schema doesn't specify
    'format': 'relativeUrl' (bmo#1289273)

  - CVE-2016-9076: select dropdown menu can be used for URL
    bar spoofing on e10s (bmo#1276976)

  - CVE-2016-9063: Possible integer overflow to fix inside
    XML_Parse in expat (bmo#1274777)

  - CVE-2016-9071: Probe browser history via HSTS/301
    redirect + CSP (bmo#1285003)

  - CVE-2016-5289: Memory safety bugs fixed in Firefox 50

  - CVE-2016-5290: Memory safety bugs fixed in Firefox 50
    and Firefox ESR 45.5

    The following vulnerabilities were fixed in Mozilla NSS
    3.26.1 :

  - CVE-2016-9074: Insufficient timing side-channel
    resistance in divSpoiler (bmo#1293334)

    Mozilla Firefox now requires mozilla-nss 3.26.2.

    New features in Mozilla Firefox :

  - Updates to keyboard shortcuts Set a preference to have
    Ctrl+Tab cycle through tabs in recently used order View
    a page in Reader Mode by using Ctrl+Alt+R

  - Added option to Find in page that allows users to limit
    search to whole words only

  - Added download protection for a large number of
    executable file types on Windows, Mac and Linux

  - Fixed rendering of dashed and dotted borders with
    rounded corners (border-radius)

  - Added a built-in Emoji set for operating systems without
    native Emoji fonts

  - Blocked versions of libavcodec older than 54.35.1

  - additional locale

    mozilla-nss was updated to 3.26.2, incorporating the
    following changes :

  - the selfserv test utility has been enhanced to support
    ALPN (HTTP/1.1) and 0-RTT

  - The following CA certificate was added: CN = ISRG Root
    X1

  - NPN is disabled and ALPN is enabled by default

  - MD5 signature algorithms sent by the server in
    CertificateRequest messages are now properly ignored"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1227538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1245791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1245795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1246945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1246972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1247239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1274777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1276976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1281071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1285003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1288482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1289273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1292159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1292443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1293334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1294438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1298552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1299686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1300083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1301777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1302973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1303418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1303678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1306696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1308922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1317641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox / Thunderbird and NSS packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-50.0.2-131.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-45.5.1-70.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.26.2-94.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.26.2-94.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
