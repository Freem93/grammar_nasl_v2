#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-126.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88547);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223", "CVE-2015-7575");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-2016-126) (SLOTH)");
  script_summary(english:"Check for the openSUSE-2016-126 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SeaMonkey was updated to 2.40 (boo#959277) to fix security issues and
bugs.

The following vulnerabilities were fixed :

  - CVE-2015-7575: MD5 signatures accepted within TLS 1.2
    ServerKeyExchange in server signature

  - CVE-2015-7201/CVE-2015-7202: Miscellaneous memory safety
    hazards

  - CVE-2015-7204: Crash with JavaScript variable assignment
    with unboxed objects

  - CVE-2015-7207: Same-origin policy violation using
    perfomance.getEntries and history navigation

  - CVE-2015-7208: Firefox allows for control characters to
    be set in cookies

  - CVE-2015-7210: Use-after-free in WebRTC when datachannel
    is used after being destroyed

  - CVE-2015-7212: Integer overflow allocating extremely
    large textures

  - CVE-2015-7215: Cross-origin information leak through web
    workers error events

  - CVE-2015-7211: Hash in data URI is incorrectly parsed

  - CVE-2015-7218/CVE-2015-7219: DOS due to malformed frames
    in HTTP/2

  - CVE-2015-7216/CVE-2015-7217: Linux file chooser crashes
    on malformed images due to flaws in Jasper library

  - CVE-2015-7203/CVE-2015-7220/CVE-2015-7221: Buffer
    overflows found through code inspection

  - CVE-2015-7205: Underflow through code inspection

  - CVE-2015-7213: Integer overflow in MP4 playback in
    64-bit versions

  - CVE-2015-7222: Integer underflow and buffer overflow
    processing MP4 metadata in libstagefright

  - CVE-2015-7223: Privilege escalation vulnerabilities in
    WebExtension APIs

  - CVE-2015-7214: Cross-site reading attack through data
    and view-source URIs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debuginfo-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debugsource-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-dom-inspector-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-irc-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-common-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-other-2.40-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debuginfo-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debugsource-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-dom-inspector-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-irc-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-common-2.40-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-other-2.40-6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}
