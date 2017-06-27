#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-568.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85837);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/08 14:15:24 $");

  script_cve_id("CVE-2015-5621");

  script_name(english:"openSUSE Security Update : net-snmp (openSUSE-2015-568)");
  script_summary(english:"Check for the openSUSE-2015-568 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"net-snmp was updated to fix one secuirty vulnerability and 2 bugs.

  - Fix an incompletely initialized vulnerability within the
    snmp_pdu_parse() function of snmp_api.c. (bnc#940188,
    CVE-2015-5621)

  - Add build requirement 'procps' to fix a net-snmp-config
    error. (bsc#935863)

  - Stop snmptrapd on removal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940188"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libsnmp30-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsnmp30-debuginfo-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-debuginfo-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-debugsource-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-devel-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-python-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"net-snmp-python-debuginfo-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-SNMP-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-SNMP-debuginfo-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"snmp-mibs-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsnmp30-32bit-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsnmp30-debuginfo-32bit-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"net-snmp-devel-32bit-5.7.2-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsnmp30-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsnmp30-debuginfo-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-debuginfo-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-debugsource-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-devel-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-python-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"net-snmp-python-debuginfo-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-SNMP-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-SNMP-debuginfo-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"snmp-mibs-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsnmp30-32bit-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsnmp30-debuginfo-32bit-5.7.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"net-snmp-devel-32bit-5.7.3-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsnmp30-32bit / libsnmp30 / libsnmp30-debuginfo-32bit / etc");
}
