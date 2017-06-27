#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-137.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75259);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-6394");

  script_name(english:"openSUSE Security Update : xtrabackup (openSUSE-SU-2014:0245-1)");
  script_summary(english:"Check for the openSUSE-2014-137 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security and non-security issues with
xtrabackup :

  - update to 2.1.7 [bnc#860488]

  - general changes :

  - rebased on MySQL versions 5.5.35 and 5.6.15

  - now uses libgcrypt randomization functions for setting
    the IV [lp#1255300] [bnc#852224] CVE-2013-6394

  - bugs fixed :

  - After being rebased on MySQL 5.6.11 Percona XtraBackup
    has been affected by the upstream bug #69780 (backward
    compatibility for InnoDB recovery) [lp#1203669]

  - Backup directory would need to be specified even for
    running the innobackupex with --help and --version
    options. [lp#1223716]

  - bugs fixed specific to MySQL 5.6 :

  - xtrabackpu did not roll back prepared XA transactions
    when applying the log. [lp#1254227]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xtrabackup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-2.1.7-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debuginfo-2.1.7-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debugsource-2.1.7-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xtrabackup / xtrabackup-debuginfo / xtrabackup-debugsource");
}
