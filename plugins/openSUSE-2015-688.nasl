#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-688.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86694);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/01/23 17:35:37 $");

  script_cve_id("CVE-2015-4813", "CVE-2015-4896");

  script_name(english:"openSUSE Security Update : VirtualBox (openSUSE-2015-688)");
  script_summary(english:"Check for the openSUSE-2015-688 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"VirtualBox was updated to 4.3.32 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-4813: Windows guests with guest additions
    installed could cause a hang or crash of VirtualBox.

  - CVE-2015-4896: Remote unauthenticated users could cause
    crash (DoS) via the network when the Remote Display
    feature (RDP) is enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951432"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected VirtualBox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.3.32_k3.16.7_29-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-4.3.32-32.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-4.3.32-32.2") ) flag++;

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
