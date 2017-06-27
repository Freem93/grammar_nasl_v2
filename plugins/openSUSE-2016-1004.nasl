#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1004.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93064);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-6172");

  script_name(english:"openSUSE Security Update : pdns (openSUSE-2016-1004)");
  script_summary(english:"Check for the openSUSE-2016-1004 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pdns fixes the following issues :

  - CVE-2016-6172: malicious primary DNS servers can crash
    secondaries through large transfers (boo#987872)

As mitigation, the xfr-max-received-mbytes config option was added,
defaulting to to 100 (MB)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987872"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pdns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"pdns-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-ldap-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-ldap-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-lua-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-lua-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mydns-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mydns-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mysql-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mysql-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-postgresql-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-postgresql-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-sqlite3-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-sqlite3-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-debuginfo-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-debugsource-3.3.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-ldap-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-ldap-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-lua-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-lua-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-mydns-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-mydns-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-mysql-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-mysql-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-postgresql-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-postgresql-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-sqlite3-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-backend-sqlite3-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-debuginfo-3.4.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pdns-debugsource-3.4.6-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns / pdns-backend-ldap / pdns-backend-ldap-debuginfo / etc");
}
