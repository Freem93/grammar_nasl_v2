#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-385.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99019);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2015-5191");

  script_name(english:"openSUSE Security Update : open-vm-tools (openSUSE-2017-385)");
  script_summary(english:"Check for the openSUSE-2017-385 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for open-vm-tools to 10.1.0 stable brings features, fixes
bugs and security issues :

  - New vmware-namespace-cmd command line utility

  - GTK3 support

  - Common Agent Framework (CAF)

  - Guest authentication with xmlsec1

  - Sub-command to push updated network information to the
    host on demand

  - Fix for quiesced snapshot failure leaving guest file
    system quiesced (bsc#1006796)

  - Fix for CVE-2015-5191 (bsc#1007600)

  - Report SLES for SAP 12 guest OS as SLES 12 (bsc#1013496)

  - Add udev rule to increase VMware virtual disk timeout
    values (bsc#994598) 

  - Fix vmtoolsd init script to run vmtoolsd in background
    (bsc#971031)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/322214"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected open-vm-tools packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvmtools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvmtools0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvmtools0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-vm-tools-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");
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

if ( rpm_check(release:"SUSE42.2", reference:"libvmtools-devel-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvmtools0-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvmtools0-debuginfo-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"open-vm-tools-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"open-vm-tools-debuginfo-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"open-vm-tools-debugsource-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"open-vm-tools-desktop-10.1.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"open-vm-tools-desktop-debuginfo-10.1.0-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvmtools-devel / libvmtools0 / libvmtools0-debuginfo / etc");
}
