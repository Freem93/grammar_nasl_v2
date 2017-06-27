#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-84.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75408);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6836", "CVE-2013-6838");

  script_name(english:"openSUSE Security Update : gnumeric (openSUSE-SU-2014:0138-1)");
  script_summary(english:"Check for the openSUSE-2014-84 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Add gnumeric-CVE-2013-6836.patch: fix
    Heap-buffer-overflow in ms_escher_get_data on a fuzzed
    xls file (bnc#856254, bgo#712772, CVE-2013-6838)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856254"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnumeric packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnumeric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnumeric-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnumeric-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnumeric-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnumeric-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/21");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"gnumeric-1.11.3-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnumeric-debuginfo-1.11.3-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnumeric-debugsource-1.11.3-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnumeric-devel-1.11.3-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"gnumeric-lang-1.11.3-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gnumeric-1.12.0-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gnumeric-debuginfo-1.12.0-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gnumeric-debugsource-1.12.0-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gnumeric-devel-1.12.0-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gnumeric-lang-1.12.0-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnumeric-1.12.7-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnumeric-debuginfo-1.12.7-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnumeric-debugsource-1.12.7-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnumeric-devel-1.12.7-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gnumeric-lang-1.12.7-2.5.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnumeric / gnumeric-debuginfo / gnumeric-debugsource / etc");
}
