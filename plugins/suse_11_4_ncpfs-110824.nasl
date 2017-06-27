#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ncpfs-5051.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75974);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1089", "CVE-2011-1679", "CVE-2011-1680");

  script_name(english:"openSUSE Security Update : ncpfs (openSUSE-SU-2011:0985-1)");
  script_summary(english:"Check for the ncpfs-5051 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Following issues are fixed by this update: The ncpfs mount and umount
programs were affected by the /etc/mtab truncation problems on
RLIMIT_FSIZE. (CVE-2011-1679)

Also on errors, the mtab lock was not removed, blocking other
applications from modifying /etc/mtab. (CVE-2011-1680)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=686554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ncpfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncpfs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ncpfs-2.2.6-169.170.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ncpfs-debuginfo-2.2.6-169.170.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ncpfs-debugsource-2.2.6-169.170.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ncpfs-devel-2.2.6-169.170.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"ncpfs-32bit-2.2.6-169.170.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"ncpfs-debuginfo-32bit-2.2.6-169.170.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncpfs");
}