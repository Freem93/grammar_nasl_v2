#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-490.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77134);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/12 14:41:11 $");

  script_cve_id("CVE-2013-6369");

  script_name(english:"openSUSE Security Update : jbigkit (openSUSE-SU-2014:0978-1)");
  script_summary(english:"Check for the openSUSE-2014-490 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issue is fixed in this update

  - [bnc#870855] - CVE-2013-6369: jbigkit buffer overflow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870855"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jbigkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jbigkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jbigkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jbigkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjbig2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
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

if ( rpm_check(release:"SUSE12.3", reference:"jbigkit-2.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjbig-devel-2.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjbig2-2.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjbig-devel-32bit-2.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjbig2-32bit-2.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"jbigkit-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"jbigkit-debuginfo-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"jbigkit-debugsource-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjbig-devel-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjbig2-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjbig2-debuginfo-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjbig-devel-32bit-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjbig2-32bit-2.0-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjbig2-debuginfo-32bit-2.0-10.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbigkit / libjbig-devel / libjbig-devel-32bit / libjbig2 / etc");
}
