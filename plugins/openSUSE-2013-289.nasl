#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-289.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74951);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/25 16:11:44 $");

  script_cve_id("CVE-2012-6139");
  script_osvdb_id(91609, 91610);

  script_name(english:"openSUSE Security Update : libxslt (openSUSE-SU-2013:0585-1)");
  script_summary(english:"Check for the openSUSE-2013-289 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two denial of service problems (crashes with NULL pointer derference)
were fixed in libxslt, which could potentially be used by remote
attackers to crash libxslt using programs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxslt1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libxslt-debugsource-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-devel-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-debuginfo-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt-python-debugsource-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt1-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libxslt1-debuginfo-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt1-32bit-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libxslt1-debuginfo-32bit-1.1.26-15.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-debugsource-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-devel-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-python-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-python-debuginfo-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-python-debugsource-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-tools-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt-tools-debuginfo-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt1-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxslt1-debuginfo-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxslt1-32bit-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxslt1-debuginfo-32bit-1.1.26-22.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-debugsource-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-devel-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-python-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-python-debuginfo-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-python-debugsource-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-tools-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt-tools-debuginfo-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt1-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxslt1-debuginfo-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxslt-devel-32bit-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxslt1-32bit-1.1.28-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxslt1-debuginfo-32bit-1.1.28-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt");
}
