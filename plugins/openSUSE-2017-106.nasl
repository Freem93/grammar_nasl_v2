#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-106.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96579);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");

  script_cve_id("CVE-2016-10109");

  script_name(english:"openSUSE Security Update : pcsc-lite (openSUSE-2017-106)");
  script_summary(english:"Check for the openSUSE-2017-106 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pcsc-lite was updated to fix one security issue.

This security issue was fixed :

  - CVE-2016-10109: This use-after-free and double-free
    issue allowed local attacker to cause a Denial of
    Service and possible privilege escalation (bsc#1017902)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017902"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcsc-lite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcsclite1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcsclite1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcsclite1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcsclite1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcscspy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcscspy0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcscspy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcscspy0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcsc-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcsc-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcsc-lite-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcsc-lite-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libpcsclite1-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcsclite1-debuginfo-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcscspy0-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpcscspy0-debuginfo-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcsc-lite-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcsc-lite-debuginfo-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcsc-lite-debugsource-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcsc-lite-devel-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcsclite1-32bit-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcsclite1-debuginfo-32bit-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcscspy0-32bit-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpcscspy0-debuginfo-32bit-1.8.11-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcsclite1-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcsclite1-debuginfo-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcscspy0-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcscspy0-debuginfo-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcsc-lite-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcsc-lite-debuginfo-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcsc-lite-debugsource-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcsc-lite-devel-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcsclite1-32bit-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcsclite1-debuginfo-32bit-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcscspy0-32bit-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcscspy0-debuginfo-32bit-1.8.14-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcsclite1-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcsclite1-debuginfo-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcscspy0-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcscspy0-debuginfo-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcsc-lite-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcsc-lite-debuginfo-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcsc-lite-debugsource-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pcsc-lite-devel-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcsclite1-32bit-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcsclite1-debuginfo-32bit-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcscspy0-32bit-1.8.17-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcscspy0-debuginfo-32bit-1.8.17-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcsclite1 / libpcsclite1-32bit / libpcsclite1-debuginfo / etc");
}
