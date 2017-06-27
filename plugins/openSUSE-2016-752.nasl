#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-752.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91723);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/21 16:59:01 $");

  script_name(english:"openSUSE Security Update : ctdb (openSUSE-2016-752)");
  script_summary(english:"Check for the openSUSE-2016-752 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ctdb was updated to fix one security issue.

This security issue was fixed :

  - bsc#969522: ctdb opening sockets with htons(IPPROTO_RAW)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969522"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ctdb packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"ctdb-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-debugsource-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-devel-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-pcp-pmda-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-pcp-pmda-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-2.5.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-debuginfo-2.5.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-debugsource-2.5.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-devel-2.5.5-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / ctdb-debugsource / ctdb-devel / etc");
}
