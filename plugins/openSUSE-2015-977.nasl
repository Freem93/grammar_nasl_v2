#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-977.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87716);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/01/23 17:35:37 $");

  script_cve_id("CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7210", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7222");

  script_name(english:"openSUSE Security Update : Mozilla Thunderbird (openSUSE-2015-977)");
  script_summary(english:"Check for the openSUSE-2015-977 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to 38.5.0 to fix multiple security
issues.

The following vulnerabilities were fixed: (boo#959277)

  - CVE-2015-7201: Miscellaneous memory safety hazards

  - CVE-2015-7210: Use-after-free in WebRTC when datachannel
    is used after being destroyed

  - CVE-2015-7212: Integer overflow allocating extremely
    large textures

  - CVE-2015-7205: Underflow through code inspection

  - CVE-2015-7213: Integer overflow in MP4 playback in
    64-bit versions

  - CVE-2015-7222: Integer underflow and buffer overflow
    processing MP4 metadata in libstagefright

  - CVE-2015-7214: Cross-site reading attack through data
    and view-source URIs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-38.5.0-70.71.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-38.5.0-34.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-buildsymbols-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debuginfo-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debugsource-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-devel-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-common-38.5.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-other-38.5.0-7.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
