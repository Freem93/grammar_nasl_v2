#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-87.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96553);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:05 $");

  script_cve_id("CVE-2016-9811");

  script_name(english:"openSUSE Security Update : gstreamer-plugins-base (openSUSE-2017-87)");
  script_summary(english:"Check for the openSUSE-2017-87 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-plugins-base fixes the following issue :

  - CVE-2016-9811: out of bounds memory read in
    windows_icon_typefind (bsc#1013669)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstAllocators-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstApp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstAudio-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstFft-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstPbutils-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstRiff-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstRtp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstRtsp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstSdp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstTag-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstVideo-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gstreamer-plugins-base-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gstreamer-plugins-base-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gstreamer-plugins-base-debugsource-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gstreamer-plugins-base-devel-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gstreamer-plugins-base-lang-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstallocators-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstallocators-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstapp-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstapp-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstaudio-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstaudio-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstfft-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstfft-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstpbutils-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstpbutils-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstriff-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstriff-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstrtp-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstrtp-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstrtsp-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstrtsp-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstsdp-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstsdp-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgsttag-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgsttag-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstvideo-1_0-0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgstvideo-1_0-0-debuginfo-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstAllocators-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstApp-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstAudio-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstFft-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstPbutils-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstRiff-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstRtp-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstRtsp-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstSdp-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstTag-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GstVideo-1_0-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstallocators-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstriff-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstrtp-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstsdp-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.4.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.4.3-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-base / gstreamer-plugins-base-32bit / etc");
}
