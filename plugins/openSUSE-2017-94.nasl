#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-94.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96558);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:05 $");

  script_cve_id("CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813");

  script_name(english:"openSUSE Security Update : gstreamer-plugins-bad (openSUSE-2017-94)");
  script_summary(english:"Check for the openSUSE-2017-94 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-plugins-bad fixes the following issues :

  - CVE-2016-9809: Off by one read in
    gst_h264_parse_set_caps() (bsc#1013659).

  - CVE-2016-9812: Out of bounds read in
    gst_mpegts_section_new (bsc#1013678).

  - CVE-2016-9813: mpegts parser: NULL pointer deref in
    _parse_pat (bsc#1013680)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013680"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-bad packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadbase-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadbase-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadbase-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadbase-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadvideo-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadvideo-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-plugins-bad-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-plugins-bad-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-plugins-bad-debugsource-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-plugins-bad-devel-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-plugins-bad-lang-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbadbase-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbadbase-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbadvideo-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbadvideo-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbasecamerabinsrc-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstbasecamerabinsrc-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstcodecparsers-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstcodecparsers-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstgl-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstgl-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstinsertbin-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstinsertbin-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstmpegts-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstmpegts-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstphotography-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstphotography-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgsturidownloader-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgsturidownloader-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstwayland-1_0-0-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgstwayland-1_0-0-debuginfo-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-plugins-bad-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-plugins-bad-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbadbase-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbadbase-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbadvideo-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbadvideo-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstcodecparsers-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstcodecparsers-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstgl-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstgl-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstinsertbin-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstinsertbin-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstmpegts-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstmpegts-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstphotography-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstphotography-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgsturidownloader-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgsturidownloader-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstwayland-1_0-0-32bit-1.4.5-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgstwayland-1_0-0-debuginfo-32bit-1.4.5-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-bad / gstreamer-plugins-bad-32bit / etc");
}
