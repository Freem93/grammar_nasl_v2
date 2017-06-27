#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-779.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91870);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-5479", "CVE-2016-3062");

  script_name(english:"openSUSE Security Update : libav (openSUSE-2016-779)");
  script_summary(english:"Check for the openSUSE-2016-779 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libav fixes the two following security issues :

  - CVE-2016-3062: A MP4 memory corruption was fixed that
    could lead to crashes or code execution. (boo#984487)

  - CVE-2015-5479: A crash due to a divide by zero was fixed
    in ff_h263_decode_mba() that could lead to decoder
    crashes. (boo#949760)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984487"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libav-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libav-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-libav56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-libav56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-libav55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-libav55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-libav5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-libav5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-libav56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-libav56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-libav2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-libav2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-libav54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-libav54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-libav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-libav3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-libav3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");
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

if ( rpm_check(release:"SUSE42.1", reference:"libav-debugsource-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libav-tools-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libav-tools-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-libav56-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-libav56-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-libav55-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-libav55-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-libav5-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-libav5-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-libav56-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-libav56-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-libav2-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-libav2-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-libav54-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-libav54-debuginfo-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-libav-devel-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-libav3-11.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-libav3-debuginfo-11.4-5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libav-debugsource / libav-tools / libav-tools-debuginfo / etc");
}
