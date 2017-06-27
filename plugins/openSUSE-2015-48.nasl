#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-48.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80926);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/23 14:31:03 $");

  script_cve_id("CVE-2014-3675", "CVE-2014-3676", "CVE-2014-3677");

  script_name(english:"openSUSE Security Update : gnu-efi / pesign / shim (openSUSE-2015-48)");
  script_summary(english:"Check for the openSUSE-2015-48 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"shim was updated to fix several security issues.

  - OOB read access when parsing DHCPv6 packets (remote DoS)
    (CVE-2014-3675).

  - Heap overflow when parsing IPv6 addresses provided by
    tftp:// DHCPv6 boot option (RCE) (CVE-2014-3676).

  - Memory corruption when processing user provided MOK
    lists (CVE-2014-3677).

More information is available at
https://bugzilla.novell.com/show_bug.cgi?id=889332

To enable this update gnu-efi was updated to 3.0u and pesign to
version 0.109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=798043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=807760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=808106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=813079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=813448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=841426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=863205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=866690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=867974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=872503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=873857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=875385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=877003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=889332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=889765"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnu-efi / pesign / shim packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnu-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pesign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pesign-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pesign-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"gnu-efi-3.0u-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pesign-0.109-3.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pesign-debuginfo-0.109-3.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"pesign-debugsource-0.109-3.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"shim-0.7.318.81ee561d-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnu-efi-3.0u-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pesign-0.109-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pesign-debuginfo-0.109-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pesign-debugsource-0.109-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"shim-0.7.318.81ee561d-7.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnu-efi / pesign / pesign-debuginfo / pesign-debugsource / shim");
}
