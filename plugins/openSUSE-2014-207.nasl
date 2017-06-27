#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-207.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75289);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-2029");

  script_name(english:"openSUSE Security Update : xtrabackup (openSUSE-SU-2014:0363-1)");
  script_summary(english:"Check for the openSUSE-2014-207 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xtrabackup was updated to 2.1.8 :

Disabled the 'binary version check' functionality in the VersionCheck
module due to security concerns. The automatic version check remains
disabled in the openSUSE package. [bnc#864194] CVE-2014-2029 More bugs
fixed :

  - do not discard read-ahead buffers through incorrect
    usage of posic_fadvise() hints, which resulted in higher
    I/O rate on the backup stage

  - Spurious trailing data blocks that would normally be
    ignored by InnoDB could lead to an assertion failure on
    the backup stage

  - A spurious warning message could cause issues with
    third-party wrapper scripts

  - xbcrypt could fail with the xbcrypt:xb_crypt_read_chunk:
    unable to read chunk iv size at offset error under some
    circumstances

  - xbstream could sometimes hang when extracting a broken
    or incomplete input stream"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864194"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xtrabackup packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/14");
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

if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-2.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debuginfo-2.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debugsource-2.1.8-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xtrabackup");
}
