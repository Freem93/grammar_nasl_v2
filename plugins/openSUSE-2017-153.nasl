#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96862);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807", "CVE-2016-9808", "CVE-2016-9810");

  script_name(english:"openSUSE Security Update : gstreamer-0_10-plugins-good (openSUSE-2017-153)");
  script_summary(english:"Check for the openSUSE-2017-153 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-0_10-plugins-good fixes the following 
issues :

  - CVE-2016-9634: Invalid FLIC files could have caused and
    an out-of-bounds write (bsc#1012102)

  - CVE-2016-9635: Invalid FLIC files could have caused and
    an out-of-bounds write (bsc#1012103)

  - CVE-2016-9636: Prevent maliciously crafted flic files
    from causing invalid memory writes (bsc#1012104)

  - CVE-2016-9807: Prevent the reading of invalid memory in
    flx_decode_chunks, leading to DoS (bsc#1013655)

  - CVE-2016-9808: Prevent maliciously crafted flic files
    from causing invalid memory accesses (bsc#1013653)

  - CVE-2016-9810: Invalid files can be used to extraneous
    unreferences, leading to invalid memory access and DoS
    (bsc#1013663)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-0_10-plugins-good packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugin-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugin-esd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugin-esd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugin-esd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-extra-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-extra-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-0_10-plugins-good-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");
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

if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugin-esd-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugin-esd-debuginfo-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-debuginfo-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-debugsource-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-extra-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-extra-debuginfo-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gstreamer-0_10-plugins-good-lang-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugin-esd-32bit-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugin-esd-debuginfo-32bit-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-good-32bit-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-good-debuginfo-32bit-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-good-extra-32bit-0.10.31-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-good-extra-debuginfo-32bit-0.10.31-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-0_10-plugin-esd / gstreamer-0_10-plugin-esd-32bit / etc");
}
