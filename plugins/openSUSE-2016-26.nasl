#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-26.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88117);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-8661", "CVE-2015-8662", "CVE-2015-8663");

  script_name(english:"openSUSE Security Update : ffmpeg (openSUSE-2016-26)");
  script_summary(english:"Check for the openSUSE-2016-26 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to ffmpeg 2.8.4 fixes the following issues :

  - CVE-2015-8661: Denial of service via crafted .mov file
    [boo#960385]

  - CVE-2015-8662: Denial of service via crafted JPEG 2000
    data [boo#960384]

  - CVE-2015-8663: Denial of service via crafted H.264 data
    [boo#960383]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960385"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-debugsource-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec56-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice56-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter5-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat56-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample2-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil54-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc53-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample1-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-devel-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale3-debuginfo-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec56-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice56-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter5-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat56-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample2-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil54-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc53-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample1-debuginfo-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-32bit-2.8.4-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale3-debuginfo-32bit-2.8.4-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / ffmpeg-devel / etc");
}
