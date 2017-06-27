#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-4926.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75424);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2010-1623", "CVE-2011-0419", "CVE-2011-1928");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2011:0859-1)");
  script_summary(english:"Check for the apache2-4926 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes :

  - CVE-2011-0419 and CVE-2011-1928: unconstrained recursion
    when processing patterns

  - CVE-2010-1623: a remote DoS (memory leak) in APR's
    reqtimeout_filter function"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=690734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693778"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"apache2-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-devel-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-example-certificates-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-example-pages-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-itk-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-prefork-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-utils-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"apache2-worker-2.2.15-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr-util1-1.3.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr-util1-dbd-mysql-1.3.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr-util1-dbd-pgsql-1.3.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr-util1-dbd-sqlite3-1.3.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr-util1-devel-1.3.9-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr1-1.3.8-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libapr1-devel-1.3.8-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapr1");
}
