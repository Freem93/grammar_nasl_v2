#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-252.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88925);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-7512", "CVE-2015-8345");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2016-252)");
  script_summary(english:"Check for the openSUSE-2016-252 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - Enforce receive packet size, thus eliminating buffer
    overflow and potential security issue. (bsc#957162
    CVE-2015-7512)

  - Infinite loop in processing command block list.
    CVE-2015-8345 (bsc#956829) :

This update also fixes a non-security bug :

  - Due to space restrictions in limited bios data areas,
    don't create mptable if vcpu count is 'high' (ie more
    than ~19). (bsc#954864) (No supported guests are
    negatively impacted by this change, which is taken from
    upstream seabios)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957162"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
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

if ( rpm_check(release:"SUSE42.1", reference:"qemu-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-debugsource-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ipxe-1.0.0-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-kvm-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-lang-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debugsource-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-seabios-1.8.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-sgabios-8-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-vgabios-1.8.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-testsuite-2.3.1-12.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
