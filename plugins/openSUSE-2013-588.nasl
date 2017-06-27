#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-588.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75088);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2007");
  script_osvdb_id(93032);

  script_name(english:"openSUSE Security Update : qemu (openSUSE-SU-2013:1202-1)");
  script_summary(english:"Check for the openSUSE-2013-588 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The qemu guest agent creates a bunch of files with insecure
permissions when started in daemon mode. For now mask all file mode
bits for 'group' and 'others' in become_daemon(). Temporarily, for
compatibility reasons, stick with the 0666 file-mode in case of files
newly created by the 'guest-file-open' QMP call. Do so without
changing the umask temporarily.

QEMU was updated to 1.1.2 on openSUSE 12.2, and 1.3.1 on openSUSE
12.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818181"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"qemu-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-debuginfo-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-debugsource-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-guest-agent-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-guest-agent-debuginfo-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-linux-user-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-tools-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qemu-tools-debuginfo-1.1.2-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-debuginfo-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-debugsource-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-guest-agent-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-guest-agent-debuginfo-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-linux-user-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-linux-user-debuginfo-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-tools-1.3.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"qemu-tools-debuginfo-1.3.1-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
