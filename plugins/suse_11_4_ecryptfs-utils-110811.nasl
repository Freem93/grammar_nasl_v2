#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ecryptfs-utils-4986.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75821);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:32 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837");

  script_name(english:"openSUSE Security Update : ecryptfs-utils (openSUSE-SU-2011:0902-1)");
  script_summary(english:"Check for the ecryptfs-utils-4986 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ecryptfs-utils fixes several security problems :

  - CVE-2011-1831 - Race condition when checking mountpoint
    during mount.

  - CVE-2011-1832 - Race condition when checking mountpoint
    during unmount.

  - CVE-2011-1833 - Race condition when checking source
    during mount.

  - CVE-2011-1834 - Improper mtab handling allowing
    corruption due to resource limits, signals, etc.

  - CVE-2011-1835 - Key poisoning in ecryptfs-setup-private
    due to insecure temp directory.

  - CVE-2011-1837 - Predictable lock counter name and
    associated races."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ecryptfs-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ecryptfs-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ecryptfs-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ecryptfs-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/11");
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

if ( rpm_check(release:"SUSE11.4", reference:"ecryptfs-utils-83-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ecryptfs-utils-debuginfo-83-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ecryptfs-utils-debugsource-83-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"ecryptfs-utils-32bit-83-6.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"ecryptfs-utils-debuginfo-32bit-83-6.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils");
}
