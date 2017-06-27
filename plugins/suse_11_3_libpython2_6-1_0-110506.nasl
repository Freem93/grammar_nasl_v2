#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpython2_6-1_0-4508.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75608);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-1521");

  script_name(english:"openSUSE Security Update : libpython2_6-1_0 (openSUSE-SU-2011:0484-1)");
  script_summary(english:"Check for the libpython2_6-1_0-4508 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of python fixes a possible denial of service bug or
information leakage vulnerability while using user-crafted ftp:// or
file:// URLs with urllib(2). CVE-2011-1521: CVSS v2 Base Score: 6.4
(AV:N/AC:L/Au:N/C:P/I:N/A:P)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-05/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpython2_6-1_0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_6-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_6-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/06");
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

if ( rpm_check(release:"SUSE11.3", reference:"libpython2_6-1_0-2.6.5-3.5.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-base-2.6.5-3.5.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-curses-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-demo-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-devel-2.6.5-3.5.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-gdbm-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-idle-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-tk-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"python-xml-2.6.5-3.5.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libpython2_6-1_0-32bit-2.6.5-3.5.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"python-32bit-2.6.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"python-base-32bit-2.6.5-3.5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython2_6-1_0 / libpython2_6-1_0-32bit / python / python-32bit / etc");
}
