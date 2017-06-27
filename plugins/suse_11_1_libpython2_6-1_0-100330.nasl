#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpython2_6-1_0-2213.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46341);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-2625", "CVE-2009-3560", "CVE-2009-3720");

  script_name(english:"openSUSE Security Update : libpython2_6-1_0 (openSUSE-SU-2010:0247-1)");
  script_summary(english:"Check for the libpython2_6-1_0-2213 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of python has a copy of libxmlrpc that is vulnerable to
denial of service bugs that can occur while processing malformed XML
input. CVE-2009-2625: CVSS v2 Base Score: 5.0 (moderate)
(AV:N/AC:L/Au:N/C:N/I:N/A:P): Permissions, Privileges, and Access
Control (CWE-264) CVE-2009-3720: CVSS v2 Base Score: 5.0 (MEDIUM)
(AV:N/AC:L/Au:N/C:N/I:N/A:P): Insufficient Information (CWE-noinfo)
CVE-2009-3560: CVSS v2 Base Score: 5.0 (MEDIUM)
(AV:N/AC:L/Au:N/C:N/I:N/A:P): Buffer Errors (CWE-119)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-05/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581765"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpython2_6-1_0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"libpython2_6-1_0-2.6.0-2.22.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-base-2.6.0-2.22.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-curses-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-demo-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-devel-2.6.0-2.22.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-gdbm-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-idle-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-tk-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-xml-2.6.0-2.22.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libpython2_6-1_0-32bit-2.6.0-2.22.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"python-32bit-2.6.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"python-base-32bit-2.6.0-2.22.23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
