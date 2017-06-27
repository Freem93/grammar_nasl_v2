#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-806.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75178);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-2065", "CVE-2013-4287", "CVE-2013-4363");
  script_bugtraq_id(59881, 62281, 62442);
  script_osvdb_id(93414, 97163);

  script_name(english:"openSUSE Security Update : ruby19 (openSUSE-SU-2013:1611-1)");
  script_summary(english:"Check for the openSUSE-2013-806 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ruby19 was updated to fix the following security issues :

  - fix CVE-2013-2065: Object taint bypassing in DL and
    Fiddle (bnc#843686) The file CVE-2013-2065.patch
    contains the patch

  - fix CVE-2013-4287 CVE-2013-4363: ruby19: Algorithmic
    complexity vulnerability (bnc#837457) The file
    CVE-2013-4287-4363.patch contains the patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby19 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
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

if ( rpm_check(release:"SUSE12.2", reference:"ruby19-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debuginfo-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debugsource-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-extra-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-doc-ri-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-debuginfo-1.9.3.p392-3.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debuginfo-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debugsource-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-extra-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-doc-ri-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-1.9.3.p392-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-debuginfo-1.9.3.p392-1.13.1") ) flag++;

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
