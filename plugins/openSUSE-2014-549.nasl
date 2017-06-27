#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-549.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77778);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/23 14:22:41 $");

  script_cve_id("CVE-2014-5461");
  script_bugtraq_id(69342);

  script_name(english:"openSUSE Security Update : lua (openSUSE-SU-2014:1145-1)");
  script_summary(english:"Check for the openSUSE-2014-549 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"lua was updated to fix an overflow in varargs functions (CVE-2014-5461
,bnc#893824)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893824"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lua packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblua5_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblua5_2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblua5_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblua5_2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lua-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/22");
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

if ( rpm_check(release:"SUSE12.3", reference:"liblua5_2-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"liblua5_2-debuginfo-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lua-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lua-debuginfo-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lua-debugsource-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lua-devel-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"liblua5_2-32bit-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"liblua5_2-debuginfo-32bit-5.2.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"liblua5_2-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"liblua5_2-debuginfo-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lua-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lua-debuginfo-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lua-debugsource-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lua-devel-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"liblua5_2-32bit-5.2.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"liblua5_2-debuginfo-32bit-5.2.2-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lua");
}
