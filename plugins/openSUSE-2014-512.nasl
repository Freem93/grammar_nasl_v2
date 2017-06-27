#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-512.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77365);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/25 15:08:47 $");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-SU-2014:1058-1)");
  script_summary(english:"Check for the openSUSE-2014-512 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libgcrypt was updated to 1.5.4 to prevent a side-channel attack on
Elgamal encryption subkeys.

Besides that the following issues were resolved :

&#9; - Improved performance of RSA, DSA, and Elgamal by using a new
exponentiation algorithm.

  - Fixed a subtle bug in mpi_set_bit which could set
    spurious bits.

  - Fixed a bug in an internal division function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891018"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/25");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-debugsource-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-devel-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt-devel-debuginfo-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt11-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgcrypt11-debuginfo-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt11-32bit-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgcrypt11-debuginfo-32bit-1.5.4-12.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-debugsource-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-devel-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-devel-debuginfo-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt11-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt11-debuginfo-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt11-32bit-1.5.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt11-debuginfo-32bit-1.5.4-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt");
}
