#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-203.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97003);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id("CVE-2016-5545", "CVE-2017-3290", "CVE-2017-3316", "CVE-2017-3332");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2017-203)");
  script_summary(english:"Check for the openSUSE-2017-203 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.1.14 fixes the following
issues :

These security issues were fixed :

  - CVE-2016-5545: Vulnerability in the GUI subcomponent of
    virtualbox allows unauthenticated attacker unauthorized
    update, insert or delete access to some data as well as
    unauthorized read access to a subset of VirtualBox
    accessible data and unauthorized ability to cause a
    partial denial of service (bsc#1020856).

  - CVE-2017-3290: Vulnerability in the Shared Folder
    subcomponent of virtualbox allows high privileged
    attacker unauthorized creation, deletion or modification
    access to critical data and unauthorized ability to
    cause a hang or frequently repeatable crash
    (bsc#1020856).

  - CVE-2017-3316: Vulnerability in the GUI subcomponent of
    virtualbox allows high privileged attacker with network
    access via multiple protocols to compromise Oracle VM
    VirtualBox (bsc#1020856).

  - CVE-2017-3332: Vulnerability in the SVGA Emulation
    subcomponent of virtualbox allows low privileged
    attacker unauthorized creation, deletion or modification
    access to critical data and unauthorized ability to
    cause a hang or frequently repeatable crash
    (bsc#1020856).

For other changes please read the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-debuginfo-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debuginfo-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debugsource-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-devel-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-desktop-icons-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-5.1.14_k4.4.36_8-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.14_k4.4.36_8-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-debuginfo-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-debuginfo-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-5.1.14_k4.4.36_8-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-debuginfo-5.1.14_k4.4.36_8-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-source-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-debuginfo-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-5.1.14-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-debuginfo-5.1.14-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
