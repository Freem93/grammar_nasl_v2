#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-302.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74640);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");
  script_osvdb_id(74829, 79249, 80009, 82462);

  script_name(english:"openSUSE Security Update : python (openSUSE-SU-2012:0667-1) (BEAST)");
  script_summary(english:"Check for the openSUSE-2012-302 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"4 vulnerabilities were discovered for the python (2.7) and python3
packages in openSUSE versions 11.4 and 12.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754677"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_2mu1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"python3-2to3-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-curses-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-curses-debuginfo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-dbm-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-dbm-debuginfo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-debuginfo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-debugsource-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-demo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-devel-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-doc-pdf-3.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-idle-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-tk-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-tk-debuginfo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-xml-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python3-xml-debuginfo-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"python3-32bit-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.1.3-6.5") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpython2_7-1_0-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpython2_7-1_0-debuginfo-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpython3_2mu1_0-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpython3_2mu1_0-debuginfo-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-base-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-base-debuginfo-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-base-debugsource-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-devel-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-doc-pdf-2.7-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-xml-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-xml-debuginfo-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-2to3-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-debuginfo-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-base-debugsource-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-devel-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-devel-debuginfo-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-doc-pdf-3.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-idle-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-tools-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-xml-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python3-xml-debuginfo-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython3_2mu1_0-32bit-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpython3_2mu1_0-debuginfo-32bit-3.2.1-5.6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"python-base-32bit-2.7.2-7.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.2-7.14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-doc-pdf / python3-2to3 / python3 / python3-32bit / etc");
}
