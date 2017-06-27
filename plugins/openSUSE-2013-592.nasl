#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-592.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75092);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-2877");
  script_bugtraq_id(61050);
  script_osvdb_id(95032);

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-SU-2013:1221-1)");
  script_summary(english:"Check for the openSUSE-2013-592 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Libxml2 was updated to fix buffer overread problems which could lead
to crashes (out of bounds read). (CVE-2013-2877)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829077"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libxml2-2-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxml2-2-debuginfo-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxml2-debugsource-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxml2-devel-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxml2-tools-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxml2-tools-debuginfo-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-libxml2-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-libxml2-debuginfo-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-libxml2-debugsource-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxml2-2-32bit-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxml2-devel-32bit-2.7.8+git20120223-8.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-2-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-2-debuginfo-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-debugsource-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-devel-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-tools-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxml2-tools-debuginfo-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-libxml2-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-libxml2-debuginfo-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-libxml2-debugsource-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.0-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.0-2.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
