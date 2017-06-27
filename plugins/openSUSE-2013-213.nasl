#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-213.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74926);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/30 14:28:48 $");

  script_cve_id("CVE-2012-0875");

  script_name(english:"openSUSE Security Update : systemtap (openSUSE-SU-2013:0475-1)");
  script_summary(english:"Check for the openSUSE-2013-213 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This systemtap updated fixes a security issue and bugs :

Security fix: Fix kernel panic when processing malformed DWARF unwind
data (bnc#748564 CVE-2012-0875)

Also bugs were fixed :

  - Change how systemtap looks for tracepoint header files
    (bnc#796574, new patch:
    systemtap-build-source-dir.patch)

  - Add libebl1 dependency. Systemtap manually loads libebl
    backends and the manual Requires: was incorrectly
    removed in a previous revision (bnc#800335)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-runtime-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemtap-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/09");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"systemtap-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-debuginfo-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-debugsource-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-runtime-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-runtime-debuginfo-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-sdt-devel-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-server-1.7-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"systemtap-server-debuginfo-1.7-3.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap");
}
