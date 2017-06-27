#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-363.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83533);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/10/23 04:40:16 $");

  script_cve_id("CVE-2015-3456");
  script_xref(name:"IAVA", value:"2015-A-0115");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2015-363) (Venom)");
  script_summary(english:"Check for the openSUSE-2015-363 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix a security issue :

  - CVE-2015-3456: Fixed a buffer overflow in the floppy
    drive emulation, which could be used to denial of
    service attacks or potential code execution against the
    host."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/14");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"qemu-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-debuginfo-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-debugsource-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-guest-agent-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-guest-agent-debuginfo-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-ipxe-1.0.0-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-lang-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-debuginfo-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-debugsource-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-seabios-1.7.2.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-sgabios-8-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-tools-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-tools-debuginfo-1.6.2-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-vgabios-0.6c-4.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
