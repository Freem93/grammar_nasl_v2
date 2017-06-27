#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-298.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74955);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0269", "CVE-2013-1821");
  script_osvdb_id(90074, 90587);

  script_name(english:"openSUSE Security Update : ruby (openSUSE-SU-2013:0603-1)");
  script_summary(english:"Check for the openSUSE-2013-298 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ruby 1.8 was updated to fix a XML entity expansion denial of service
attack (CVE-2013-1821)

Ruby 1.9 was updated to 1.9.3 p392, fixing the same security issues
and also :

  - update json intree to 1.5.5: Denial of Service and
    Unsafe Object Creation Vulnerability in JSON
    CVE-2013-0269

  - limit entity expansion text limit to 10kB CVE-2013-1821

  - get rid of a SEGV when calling rb_iter_break() from some
    extention libraries.

  - some warning suppressed and smaller fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808137"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"ruby-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-debuginfo-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-debugsource-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-devel-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-doc-html-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-doc-ri-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-examples-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-test-suite-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-tk-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ruby-tk-debuginfo-1.8.7.p357-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby-1.9.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby-common-1.9.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby-devel-1.9.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debuginfo-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-debugsource-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-devel-extra-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-doc-ri-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ruby19-tk-debuginfo-1.9.3.p392-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby-1.9.3-15.2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby-devel-1.9.3-15.2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debuginfo-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debugsource-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-extra-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-doc-ri-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-1.9.3.p392-1.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-debuginfo-1.9.3.p392-1.5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
