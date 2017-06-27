#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-364.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83534);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2015/10/23 04:40:16 $");

  script_cve_id("CVE-2015-3456");
  script_xref(name:"IAVA", value:"2015-A-0115");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2015-364) (Venom)");
  script_summary(english:"Check for the openSUSE-2015-364 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Qemu was updated to v2.1.3: See
http://wiki.qemu-project.org/ChangeLog/2.1 for more information.

This update includes a security fix :

  - CVE-2015-3456: Fixed a buffer overflow in the floppy
    drive emulation, which could be used to denial of
    service attacks or potential code execution against the
    host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wiki.qemu-project.org/ChangeLog/2.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929339"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcacard-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcacard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcacard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"libcacard-debugsource-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcacard-devel-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcacard0-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcacard0-debuginfo-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-arm-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-arm-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-block-curl-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-block-curl-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-debugsource-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-extra-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-extra-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-guest-agent-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-guest-agent-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-ipxe-1.0.0-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-ksm-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-kvm-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-lang-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-linux-user-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-linux-user-debuginfo-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-linux-user-debugsource-2.1.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-ppc-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-ppc-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-s390-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-s390-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-seabios-1.7.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-sgabios-8-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-tools-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-tools-debuginfo-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-vgabios-1.7.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-x86-2.1.3-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"qemu-x86-debuginfo-2.1.3-7.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard-debugsource / libcacard-devel / libcacard0 / etc");
}
