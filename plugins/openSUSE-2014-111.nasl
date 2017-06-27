#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-111.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75249);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4344");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-SU-2014:0200-1)");
  script_summary(english:"Check for the openSUSE-2014-111 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Running QEMU in a configuration with more than 256 emulated SCSI
devices attached could have caused a buffer overflow when the guest
issues a REPORT LUNS command. Fix this as part of upgrading to the
latest stable version on 13.1. Also fix unintentional building against
gtk2 rather than gtk3 on 13.1, and fix serial retry logic on 12.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849587"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"qemu-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-debuginfo-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-debugsource-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-guest-agent-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-guest-agent-debuginfo-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-linux-user-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-linux-user-debuginfo-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-tools-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-tools-debuginfo-1.3.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-debuginfo-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-debugsource-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-guest-agent-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-guest-agent-debuginfo-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-ipxe-1.0.0-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-lang-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-debuginfo-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-linux-user-debugsource-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-seabios-1.7.2.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-sgabios-8-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-tools-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-tools-debuginfo-1.6.2-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"qemu-vgabios-0.6c-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-debuginfo / qemu-debugsource / qemu-guest-agent / etc");
}
