#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libvmtools-devel-4693.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75626);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-1681", "CVE-2011-1787", "CVE-2011-2145", "CVE-2011-2146");

  script_name(english:"openSUSE Security Update : libvmtools-devel (openSUSE-SU-2011:0617-1)");
  script_summary(english:"Check for the libvmtools-devel-4693 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of open-vm-tools fixes the following vulnerabilities which
allowed an attacker to gain root privileges within the guest system :

  - CVE-2011-1681

  - CVE-2011-2146

  - CVE-2011-1787

  - CVE-2011-2145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-06/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=690491"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvmtools-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvmtools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvmtools0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"libvmtools-devel-2011.05.27-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libvmtools0-2011.05.27-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"open-vm-tools-2011.05.27-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"open-vm-tools-gui-2011.05.27-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"vmware-guest-kmp-default-2011.05.27_k2.6.34.8_0.2-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"vmware-guest-kmp-desktop-2011.05.27_k2.6.34.8_0.2-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"vmware-guest-kmp-pae-2011.05.27_k2.6.34.8_0.2-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "open-vm-tools");
}
