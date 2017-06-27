#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1184.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94060);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 17:03:08 $");

  script_cve_id("CVE-2016-7796");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2016-1184)");
  script_summary(english:"Check for the openSUSE-2016-1184 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

  - CVE-2016-7796: A zero-length message received over
    systemd's notification socket could make
    manager_dispatch_notify_fd() return an error and, as a
    side effect, disable the notification handler
    completely. As the notification socket is
    world-writable, this could have allowed a local user to
    perform a denial-of-service attack against systemd.
    (bsc#1001765)

Additionally, the following non-security fixes are included :

  - Fix HMAC calculation when appending a data object to
    journal. (bsc#1000435)

  - Never accept file descriptors from file systems with
    mandatory locking enabled. (bsc#954374)

  - Do not warn about missing install info with 'preset'.
    (bsc#970293) 

  - Save /run/systemd/users/UID before starting
    user@.service. (bsc#996269)

  - Make sure that /var/lib/systemd/sysv-convert/database is
    always initialized. (bsc#982211)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996269"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-gateway-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GUdev-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-0-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-0-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-devel-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-devel-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini-devel-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini1-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini1-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev1-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev1-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nss-myhostname-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nss-myhostname-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-bash-completion-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-debugsource-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-devel-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-journal-gateway-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-journal-gateway-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-logger-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-debugsource-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-devel-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-sysvinit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-sysvinit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GUdev-1_0-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-mini-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-mini-debuginfo-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgudev-1_0-0-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libudev1-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"nss-myhostname-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"systemd-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-210.1475218254.1e76ce0-25.48.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libudev-mini-devel / libudev-mini1 / libudev-mini1-debuginfo / etc");
}
