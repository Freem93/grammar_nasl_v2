#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-481.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99430);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2017-7418");

  script_name(english:"openSUSE Security Update : proftpd (openSUSE-2017-481)");
  script_summary(english:"Check for the openSUSE-2017-481 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for proftpd to version 1.3.5d fixes the following issues :

This security issue was fixed :

  - CVE-2017-7418: ProFTPD checked only the last path
    component when enforcing AllowChrootSymlinks. Attackers
    with local access could bypass the AllowChrootSymlinks
    control by replacing a path component (other than the
    last one) with a symbolic link (bsc#1032443).

These non-security issues were fixed :

  - Reduce TLS protocols to TLSv1.1 and TLSv1.2

  - Disable TLSCACertificateFile

  - Add TLSCertificateChainFile

  - All FTP logins are treated as anonymous logins again

  - SSH rekey during authentication could have caused issues
    with clients.

  - Recursive SCP uploads of multiple directories were not
    handled properly.

  - LIST returned different results for file, depending on
    path syntax.

  - 'AuthAliasOnly on' in server config broke anonymous
    logins.

  - Fixed memory leak when mod_facl is used.

  - Fix systemd vs SysVinit inconsistency"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");
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

if ( rpm_check(release:"SUSE42.1", reference:"proftpd-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-debugsource-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-devel-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-lang-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-ldap-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-ldap-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-mysql-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-mysql-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-pgsql-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-pgsql-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-radius-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-radius-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-sqlite-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"proftpd-sqlite-debuginfo-1.3.5d-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-debuginfo-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-debugsource-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-devel-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-lang-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-ldap-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-ldap-debuginfo-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-mysql-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-mysql-debuginfo-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-pgsql-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-pgsql-debuginfo-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-radius-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-radius-debuginfo-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-sqlite-1.3.5d-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"proftpd-sqlite-debuginfo-1.3.5d-6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd / proftpd-debuginfo / proftpd-debugsource / proftpd-devel / etc");
}
