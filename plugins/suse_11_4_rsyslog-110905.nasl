#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update rsyslog-5099.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76013);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2011-3200");
  script_osvdb_id(74864);

  script_name(english:"openSUSE Security Update : rsyslog (openSUSE-SU-2011:1020-1)");
  script_summary(english:"Check for the rsyslog-5099 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Specially crafted log messages could crash rsyslogd (CVE-2011-3200)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714658"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-diag-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-diag-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-dbi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gtls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-debugsource-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-diag-tools-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-diag-tools-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-dbi-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-dbi-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-gssapi-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-gssapi-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-gtls-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-gtls-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-mysql-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-mysql-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-pgsql-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-pgsql-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-relp-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-relp-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-snmp-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-snmp-debuginfo-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-udpspoof-5.6.5-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rsyslog-module-udpspoof-debuginfo-5.6.5-1.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-diag-tools / rsyslog-module-dbi / etc");
}
