#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-333.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74655);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / mozilla-nss / etc (openSUSE-SU-2012:0760-1)");
  script_summary(english:"Check for the openSUSE-2012-333 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in MozillaFirefox :

  - update to Firefox 13.0 (bnc#765204)

  - MFSA 2012-34/CVE-2012-1938/CVE-2012-1937/CVE-2011-3101
    Miscellaneous memory safety hazards

  - MFSA 2012-36/CVE-2012-1944 (bmo#751422) Content Security
    Policy inline-script bypass

  - MFSA 2012-37/CVE-2012-1945 (bmo#670514) Information
    disclosure though Windows file shares and shortcut files

  - MFSA 2012-38/CVE-2012-1946 (bmo#750109) Use-after-free
    while replacing/inserting a node in a document

  - MFSA 2012-40/CVE-2012-1947/CVE-2012-1940/CVE-2012-1941
    Buffer overflow and use-after-free issues found using
    Address Sanitizer

  - require NSS 3.13.4

  - MFSA 2012-39/CVE-2012-0441 (bmo#715073)

  - fix sound notifications when filename/path contains a
    whitespace (bmo#749739)

  - fix build on arm

  - reenabled crashreporter for Factory/12.2 (fix in
    mozilla-gcc47.patch)

Changes in MozillaThunderbird :

  - update to Thunderbird 13.0 (bnc#765204)

  - MFSA 2012-34/CVE-2012-1938/CVE-2012-1937/CVE-2011-3101
    Miscellaneous memory safety hazards

  - MFSA 2012-36/CVE-2012-1944 (bmo#751422) Content Security
    Policy inline-script bypass

  - MFSA 2012-37/CVE-2012-1945 (bmo#670514) Information
    disclosure though Windows file shares and shortcut files

  - MFSA 2012-38/CVE-2012-1946 (bmo#750109) Use-after-free
    while replacing/inserting a node in a document

  - MFSA 2012-40/CVE-2012-1947/CVE-2012-1940/CVE-2012-1941
    Buffer overflow and use-after-free issues found using
    Address Sanitizer

  - require NSS 3.13.4

  - MFSA 2012-39/CVE-2012-0441 (bmo#715073)

  - fix build with system NSPR (mozilla-system-nspr.patch)

  - add dependentlibs.list for improved XRE startup

  - update enigmail to 1.4.2

  - reenabled crashreporter for Factory/12.2 (fix in
    mozilla-gcc47.patch)

  - update to Thunderbird 12.0.1

  - fix regressions

  - POP3 filters (bmo#748090)

  - Message Body not loaded when using 'Fetch Headers Only'
    (bmo#748865)

  - Received messages contain parts of other messages with
    movemail account (bmo#748726)

  - New mail notification issue (bmo#748997)

  - crash in nsMsgDatabase::MatchDbName (bmo#748432)

  - fixed build with gcc 4.7

Changes in seamonkey :

  - update to SeaMonkey 2.10 (bnc#765204)

  - MFSA 2012-34/CVE-2012-1938/CVE-2012-1937/CVE-2011-3101
    Miscellaneous memory safety hazards

  - MFSA 2012-36/CVE-2012-1944 (bmo#751422) Content Security
    Policy inline-script bypass

  - MFSA 2012-37/CVE-2012-1945 (bmo#670514) Information
    disclosure though Windows file shares and shortcut files

  - MFSA 2012-38/CVE-2012-1946 (bmo#750109) Use-after-free
    while replacing/inserting a node in a document

  - MFSA 2012-40/CVE-2012-1947/CVE-2012-1940/CVE-2012-1941
    Buffer overflow and use-after-free issues found using
    Address Sanitizer

  - requires NSS 3.13.4

  - MFSA 2012-39/CVE-2012-0441 (bmo#715073)

  - update to SeaMonkey 2.9.1

  - fix regressions

  - POP3 filters (bmo#748090)

  - Message Body not loaded when using 'Fetch Headers Only'
    (bmo#748865)

  - Received messages contain parts of other messages with
    movemail account (bmo#748726)

  - New mail notification issue (bmo#748997)

  - crash in nsMsgDatabase::MatchDbName (bmo#748432)

  - fixed build with gcc 4.7

Changes in mozilla-nss :

  - update to 3.13.5 RTM

  - update to 3.13.4 RTM

  - fixed some bugs

  - fixed cert verification regression in PKIX mode
    (bmo#737802) introduced in 3.13.2

Changes in xulrunner :

  - update to 13.0 (bnc#765204)

  - MFSA 2012-34/CVE-2012-1938/CVE-2012-1937/CVE-2011-3101
    Miscellaneous memory safety hazards

  - MFSA 2012-36/CVE-2012-1944 (bmo#751422) Content Security
    Policy inline-script bypass

  - MFSA 2012-37/CVE-2012-1945 (bmo#670514) Information
    disclosure though Windows file shares and shortcut files

  - MFSA 2012-38/CVE-2012-1946 (bmo#750109) Use-after-free
    while replacing/inserting a node in a document

  - MFSA 2012-40/CVE-2012-1947/CVE-2012-1940/CVE-2012-1941
    Buffer overflow and use-after-free issues found using
    Address Sanitizer

  - require NSS 3.13.4

  - MFSA 2012-39/CVE-2012-0441 (bmo#715073)

  - reenabled crashreporter for Factory/12.2 (fixed in
    mozilla-gcc47.patch)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-06/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765204"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / mozilla-nss / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-13.0-25.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.4.2+13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.4.2+13.0-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debugsource-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-devel-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-debuginfo-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debuginfo-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debugsource-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-dom-inspector-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-irc-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-common-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-other-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-venkman-2.10-21.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.5-44.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-13.0-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-1.99.08-2.18.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-1.99.08-2.18.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-1.99.08-2.18.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.2+13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.2+13.0-33.23.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.10-2.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.5-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-13.0-2.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-13.0-2.29.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaThunderbird / mozilla-nss / seamonkey / xulrunner");
}
