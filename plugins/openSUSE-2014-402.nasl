#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-402.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75380);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-3146");

  script_name(english:"openSUSE Security Update : python-lxml (openSUSE-SU-2014:0735-1)");
  script_summary(english:"Check for the openSUSE-2014-402 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"python-lxml was fixed to ensure proper input sanitization in
clean_html (CVE-2014-3146)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877258"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-lxml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-lxml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-lxml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-lxml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-lxml-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/23");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"python-lxml-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-lxml-debuginfo-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-lxml-debugsource-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-lxml-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-lxml-debuginfo-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-lxml-debugsource-2.3.4-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-lxml-3.2.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-lxml-debuginfo-3.2.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-lxml-debugsource-3.2.3-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-lxml");
}
