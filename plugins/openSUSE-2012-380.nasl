#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-380.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74675);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2135");

  script_name(english:"openSUSE Security Update : python3 (openSUSE-SU-2012:0861-1)");
  script_summary(english:"Check for the openSUSE-2012-380 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"python3 was fixed for :

  - Fix bnc#758993 - CVE-2012-2135: python3 utf-16 decoder
    unicode_decode_call_errorhandler aligned_end is not
    updated"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-2to3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/04");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libpython3_2mu1_0-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpython3_2mu1_0-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-2to3-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-debugsource-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-curses-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-curses-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-dbm-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-dbm-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-debugsource-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-devel-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-devel-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-doc-pdf-3.2-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-idle-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-tk-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-tk-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-tools-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-xml-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-xml-debuginfo-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython3_2mu1_0-32bit-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython3_2mu1_0-debuginfo-32bit-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"python3-32bit-3.2.1-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.2.1-5.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3");
}
