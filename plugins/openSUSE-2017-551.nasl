#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-551.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100037);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2017-5495");

  script_name(english:"openSUSE Security Update : quagga (openSUSE-2017-551)");
  script_summary(english:"Check for the openSUSE-2017-551 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for quagga to version 1.1.1 fixes the following issues :

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
    from quagga.log to zebra.log.

  - Added libfpm_pb0 and libquagga_pb0 shared library
    sub-packages, adjusted libzebra0 sub-package name to
    libzebra1.

  - Do not enable zebra's tcp interface (port 2600) to use
    default unix socket for communication between the
    daemons 

A digest of the other changes by the version upgrade :

  - isisd: Fix size of malloc

  - isisd: check for the existance of the correct list

  - ospf6d: fix off-by-one on display of spf reasons

  - ospf6d: don't access nexthops out of bounds

  - bgpd: fix off-by-one in attribute flags handling

  - bgpd: Fix buffer overflow error in bgp_dump_routes_func

Please
http://mirror.easyname.at/nongnu/quagga/quagga-1.1.1.changelog.txt and
the changelog for a complete list of changes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mirror.easyname.at/nongnu/quagga/quagga-1.1.1.changelog.txt"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfpm_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfpm_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospfapiclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libospfapiclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquagga_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquagga_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzebra1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzebra1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libfpm_pb0-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfpm_pb0-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libospf0-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libospf0-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libospfapiclient0-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libospfapiclient0-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libquagga_pb0-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libquagga_pb0-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzebra1-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzebra1-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"quagga-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"quagga-debuginfo-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"quagga-debugsource-1.1.1-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"quagga-devel-1.1.1-16.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfpm_pb0 / libfpm_pb0-debuginfo / libospf0 / libospf0-debuginfo / etc");
}
