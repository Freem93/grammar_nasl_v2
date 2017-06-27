#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-547.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100035);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2017-5495");

  script_name(english:"openSUSE Security Update : quagga (openSUSE-2017-547)");
  script_summary(english:"Check for the openSUSE-2017-547 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for quagga fixes the following issues :

This security issue was fixed :

  - CVE-2017-5495: Quagga was vulnerable to an unbounded
    memory allocation in the telnet 'vty' CLI, leading to a
    Denial-of-Service of Quagga daemons, or even the entire
    host. When Quagga daemons are configured with their
    telnet CLI enabled, anyone who can connect to the TCP
    ports can trigger this vulnerability, prior to
    authentication (bsc#1021669).

These non-security issues were fixed :

  - Disabled passwords in default zebra.conf config file,
    causing to disable vty telnet interface by default. The
    vty interface is available via 'vtysh' utility using pam
    authentication to permit management access for root
    without password (boo#1021669).

  - Changed owner of /etc/quagga to quagga:quagga to permit
    to manage quagga via vty interface.

  - Added quagga.log and create and su statemets to
    logrotate config, changed default zebra log file name
    from quagga.log to zebra.log."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"quagga-0.99.24.1-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quagga-debuginfo-0.99.24.1-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quagga-debugsource-0.99.24.1-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quagga-devel-0.99.24.1-17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-debuginfo / quagga-debugsource / quagga-devel");
}
