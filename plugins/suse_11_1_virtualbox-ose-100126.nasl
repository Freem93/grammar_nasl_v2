#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update virtualbox-ose-1874.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44369);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 19:55:06 $");

  script_cve_id("CVE-2009-3940");

  script_name(english:"openSUSE Security Update : virtualbox-ose (virtualbox-ose-1874)");
  script_summary(english:"Check for the virtualbox-ose-1874 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of virtualbox-ose fixes a memory consumption bug in the
kernel code that can be used to allocate almost all physical memory.
CVE-2009-3940: CVSS v2 Base Score: 2.1 (LOW)
(AV:L/AC:L/Au:N/C:N/I:N/A:P)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox-ose packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-driver-virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-2.0.6-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-guest-tools-2.0.6-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.42_0.1-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-default-2.0.6_2.6.27.42_0.1-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-pae-2.0.6_2.6.27.42_0.1-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.42_0.1-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xorg-x11-driver-virtualbox-ose-2.0.6-2.9.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virtualbox-ose");
}
