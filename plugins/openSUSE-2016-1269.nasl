#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1269.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94600);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/07 17:42:52 $");

  script_cve_id("CVE-2015-0245");

  script_name(english:"openSUSE Security Update : dbus-1 (openSUSE-2016-1269)");
  script_summary(english:"Check for the openSUSE-2016-1269 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dbus-1 to version 1.8.22 fixes several issues.

This security issue was fixed :

  - boo#1003898: Do not treat ActivationFailure message
    received from root-owned systemd name as a format
    string.

    These non-security issues were fixed :

  - boo#978477: Correctly reset timeouts for pending file
    descriptors

  - boo#980928: increase listen() backlog of AF_UNIX sockets
    to SOMAXCONN

  - Change the default configuration for the session bus to
    only allow EXTERNAL authentication (secure
    kernel-mediated credentials-passing), as was already
    done for the system bus.

  - Fix a memory leak when GetConnectionCredentials()
    succeeds (fdo#91008)

  - Ensure that dbus-monitor does not reply to messages
    intended for others (fdo#90952)

  - Add locking to DBusCounter's reference count and notify
    function (fdo#89297)

  - Ensure that DBusTransport's reference count is protected
    by the corresponding DBusConnection's lock (fdo#90312)

  - Correctly release DBusServer mutex before early-return
    if we run out of memory while copying authentication
    mechanisms (fdo#90021)

  - Correctly initialize all fields of DBusTypeReader
    (fdo#90021)

  - Fix some missing \n in verbose (debug log) messages
    (fdo#90004)

  - Clean up some memory leaks in test code (fdo#90021)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=87999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=89297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=90004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=90021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=90312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=90952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=91008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freedesktop.org/show_bug.cgi?id=98157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980928"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/07");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debuginfo-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debugsource-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-devel-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debuginfo-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debugsource-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-debuginfo-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.8.22-4.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.8.22-4.39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1 / dbus-1-debuginfo / dbus-1-debuginfo-32bit / dbus-1-x11 / etc");
}
