#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-431.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75005);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2013-1960", "CVE-2013-1961");
  script_osvdb_id(92986, 92987);

  script_name(english:"openSUSE Security Update : tiff (openSUSE-SU-2013:0944-1)");
  script_summary(english:"Check for the openSUSE-2013-431 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libtiff security update :

  - CVE-2013-1961.patch [bnc#818117]

  - CVE-2013-1960.patch [bnc#817573]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818117"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/11");
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

if ( rpm_check(release:"SUSE12.1", reference:"libtiff-devel-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtiff3-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtiff3-debuginfo-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tiff-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tiff-debuginfo-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tiff-debugsource-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtiff-devel-32bit-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtiff3-32bit-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtiff3-debuginfo-32bit-3.9.5-8.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libtiff-devel-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libtiff5-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libtiff5-debuginfo-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-debuginfo-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-debugsource-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.2-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff-devel-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff5-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff5-debuginfo-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-debuginfo-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-debugsource-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.3-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
