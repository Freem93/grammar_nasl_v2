#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-425.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76104);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/18 10:46:16 $");

  script_cve_id("CVE-2014-3956");

  script_name(english:"openSUSE Security Update : sendmail (openSUSE-SU-2014:0804-1)");
  script_summary(english:"Check for the openSUSE-2014-425 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"sendmail was updated to properly close file descriptors before
executing programs.

These security issues were fixed :

  - Not properly closing file descriptors before executing
    programs (CVE-2014-3956)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881284"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sendmail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendmail-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uucp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uucp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uucp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
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

if ( rpm_check(release:"SUSE12.3", reference:"rmail-8.14.3-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rmail-debuginfo-8.14.3-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sendmail-8.14.5-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sendmail-debuginfo-8.14.5-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sendmail-debugsource-8.14.5-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sendmail-devel-8.14.5-85.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"uucp-1.07-85.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"uucp-debuginfo-1.07-85.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"uucp-debugsource-1.07-85.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rmail-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rmail-debuginfo-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"sendmail-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"sendmail-debuginfo-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"sendmail-debugsource-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"sendmail-devel-8.14.7-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"uucp-1.07-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"uucp-debuginfo-1.07-92.5.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"uucp-debugsource-1.07-92.5.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail");
}
