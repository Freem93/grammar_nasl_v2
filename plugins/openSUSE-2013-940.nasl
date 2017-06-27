#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-940.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75221);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2013-4164");
  script_bugtraq_id(63873);
  script_osvdb_id(100113);

  script_name(english:"openSUSE Security Update : ruby19 (openSUSE-SU-2013:1835-1)");
  script_summary(english:"Check for the openSUSE-2013-940 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"The following security issue was fixed in ruby19 :"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851803"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby19 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"ruby19-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debuginfo-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debugsource-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-extra-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-doc-ri-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-debuginfo-1.9.3.p392-3.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debuginfo-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debugsource-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-extra-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-doc-ri-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-debuginfo-1.9.3.p392-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-debuginfo-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-debugsource-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-devel-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-devel-extra-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-doc-ri-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-tk-1.9.3.p448-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-tk-debuginfo-1.9.3.p448-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-debugsource / ruby19-devel / etc");
}
