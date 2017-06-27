#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-491.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99499);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id("CVE-2016-2775", "CVE-2016-6170", "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");
  script_xref(name:"IAVA", value:"2017-A-0004");
  script_xref(name:"IAVA", value:"2017-A-0120");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2017-491)");
  script_summary(english:"Check for the openSUSE-2017-491 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following issues :

CVE-2017-3137 (bsc#1033467): Mistaken assumptions about the ordering
of records in the answer section of a response containing CNAME or
DNAME resource records could have been exploited to cause a denial of
service of a bind server performing recursion.

CVE-2017-3136 (bsc#1033466): An attacker could have constructed a
query that would cause a denial of service of servers configured to
use DNS64.

CVE-2017-3138 (bsc#1033468): An attacker with access to the BIND
control channel could have caused the server to stop by triggering an
assertion failure.

CVE-2016-6170 (bsc#987866): Primary DNS servers could have caused a
denial of service of secondary DNS servers via a large AXFR response.
IXFR servers could have caused a denial of service of IXFR clients via
a large IXFR response. Remote authenticated users could have caused a
denial of service of primary DNS servers via a large UPDATE message.

CVE-2016-2775 (bsc#989528): When lwresd or the named lwres option were
enabled, bind allowed remote attackers to cause a denial of service
(daemon crash) via a long request that uses the lightweight resolver
protocol.

One additional non-security bug was fixed :

The default umask was changed to 077. (bsc#1020983)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989528"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"bind-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-chrootenv-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-debuginfo-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-debugsource-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-devel-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-libs-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-libs-debuginfo-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-lwresd-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-lwresd-debuginfo-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-utils-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bind-utils-debuginfo-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"bind-libs-32bit-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.9P1-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-chrootenv-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-debuginfo-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-debugsource-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-devel-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-libs-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-libs-debuginfo-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-lwresd-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-lwresd-debuginfo-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-utils-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bind-utils-debuginfo-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"bind-libs-32bit-9.9.9P1-48.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.9P1-48.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
