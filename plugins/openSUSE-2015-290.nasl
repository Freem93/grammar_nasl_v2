#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-290.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82651);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2015-0799", "CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / mozilla-nspr (openSUSE-2015-290)");
  script_summary(english:"Check for the openSUSE-2015-290 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox and Thunderbird were updated to fix several important
vulnerabilities.

Mozilla Firefox was updated to 37.0.1. Mozilla Thunderbird was updated
to 31.6.0. mozilla-nspr was updated to 4.10.8 as a dependency.

The following vulnerabilities were fixed in Mozilla Firefox :

  - Miscellaneous memory safety hazards (MFSA
    2015-30/CVE-2015-0814/CVE-2015-0815 boo#925392)

  - Use-after-free when using the Fluendo MP3 GStreamer
    plugin (MFSA 2015-31/CVE-2015-0813 bmo#1106596
    boo#925393)

  - Add-on lightweight theme installation approval bypassed
    through MITM attack (MFSA 2015-32/CVE-2015-0812
    bmo#1128126 boo#925394)

  - resource:// documents can load privileged pages (MFSA
    2015-33/CVE-2015-0816 bmo#1144991 boo#925395)

  - Out of bounds read in QCMS library
    (MFSA-2015-34/CVE-2015-0811 bmo#1132468 boo#925396)

  - Incorrect memory management for simple-type arrays in
    WebRTC (MFSA-2015-36/CVE-2015-0808 bmo#1109552
    boo#925397)

  - CORS requests should not follow 30x redirections after
    preflight (MFSA-2015-37/CVE-2015-0807 bmo#1111834
    boo#925398)

  - Memory corruption crashes in Off Main Thread Compositing
    (MFSA-2015-38/CVE-2015-0805/CVE-2015-0806 bmo#1135511
    bmo#1099437 boo#925399)

  - Use-after-free due to type confusion flaws
    (MFSA-2015-39/CVE-2015-0803/CVE-2015-0804 (mo#1134560
    boo#925400)

  - Same-origin bypass through anchor navigation
    (MFSA-2015-40/CVE-2015-0801 bmo#1146339 boo#925401)

  - Windows can retain access to privileged content on
    navigation to unprivileged pages
    (MFSA-2015-42/CVE-2015-0802 bmo#1124898 boo#925402)

The following vulnerability was fixed in functionality that was not
released as an update to openSUSE :

  - Certificate verification could be bypassed through the
    HTTP/2 Alt-Svc header (MFSA 2015-44/CVE-2015-0799
    bmo#1148328 bnc#926166)

The functionality added in 37.0 and thus removed in 37.0.1 was :

  - Opportunistically encrypt HTTP traffic where the server
    supports HTTP/2 AltSvc

The following functionality was added or updated in Mozilla Firefox :

  - Heartbeat user rating system

  - Yandex set as default search provider for the Turkish
    locale

  - Bing search now uses HTTPS for secure searching

  - Improved protection against site impersonation via
    OneCRL centralized certificate revocation

  - some more behaviour changes for TLS

The following vulnerabilities were fixed in Mozilla Thunderbird :

  - Miscellaneous memory safety hazards (MFSA
    2015-30/CVE-2015-0814/CVE-2015-0815 boo#925392)

  - Use-after-free when using the Fluendo MP3 GStreamer
    plugin (MFSA 2015-31/CVE-2015-0813 bmo#1106596
    boo#925393)

  - resource:// documents can load privileged pages (MFSA
    2015-33/CVE-2015-0816 bmo#1144991 boo#925395)

  - CORS requests should not follow 30x redirections after
    preflight (MFSA-2015-37/CVE-2015-0807 bmo#1111834
    boo#925398)

  - Same-origin bypass through anchor navigation
    (MFSA-2015-40/CVE-2015-0801 bmo#1146339 boo#925401)

mozilla-nspr was updated to 4.10.8 as a dependency and received the
following changes :

  - bmo#573192: remove the stack-based PRFileDesc cache.

  - bmo#756047: check for _POSIX_THREAD_PRIORITY_SCHEDULING
    > 0 instead of only checking if the identifier is
    defined.

  - bmo#1089908: Fix variable shadowing in _PR_MD_LOCKFILE.
    Use PR_ARRAY_SIZE to get the array size of
    _PR_RUNQ(t->cpu).

  - bmo#1106600: Replace PR_ASSERT(!'foo') with
    PR_NOT_REACHED('foo') to fix clang -Wstring-conversion
    warnings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926166"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / mozilla-nspr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-37.0.1-68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-31.6.0-70.50.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debuginfo-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debugsource-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-devel-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-37.0.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-31.6.0-15.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-4.10.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debuginfo-4.10.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debugsource-4.10.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-devel-4.10.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.8-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.8-6.1") ) flag++;

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
