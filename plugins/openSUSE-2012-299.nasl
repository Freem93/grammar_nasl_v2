#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-299.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74638);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2141");
  script_osvdb_id(81636);

  script_name(english:"openSUSE Security Update : net-snmp (openSUSE-SU-2012:0659-1)");
  script_summary(english:"Check for the openSUSE-2012-299 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SNMP GET request involving on a non-existent extension table entry
could crash snmpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759352"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp25-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp25-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp25-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libsnmp25-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsnmp25-debuginfo-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"net-snmp-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"net-snmp-debuginfo-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"net-snmp-debugsource-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"net-snmp-devel-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"perl-SNMP-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"perl-SNMP-debuginfo-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"snmp-mibs-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsnmp25-32bit-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsnmp25-debuginfo-32bit-5.6.1-4.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsnmp30-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsnmp30-debuginfo-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"net-snmp-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"net-snmp-debuginfo-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"net-snmp-debugsource-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"net-snmp-devel-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-SNMP-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-SNMP-debuginfo-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"snmp-mibs-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsnmp30-32bit-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsnmp30-debuginfo-32bit-5.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"net-snmp-devel-32bit-5.7.1-3.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsnmp25-32bit / libsnmp25 / libsnmp25-debuginfo-32bit / etc");
}
