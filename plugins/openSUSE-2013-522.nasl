#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-522.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75053);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2013-2132");

  script_name(english:"openSUSE Security Update : python-pymongo / python3-pymongo (openSUSE-SU-2013:1064-1)");
  script_summary(english:"Check for the openSUSE-2013-522 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pymongo fixes a NULL pointer issue.

  - Add Fix-null-pointer-when-decoding-invalid-DBRef.patch

  - Fixed user-triggerable NULL pointer dereference due to
    utter plebbery (CVE-2013-2132, bnc#822798)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822798"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-pymongo / python3-pymongo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pymongo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-pymongo-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/05");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"python-pymongo-2.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-pymongo-debuginfo-2.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-pymongo-debugsource-2.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-pymongo-2.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-pymongo-debuginfo-2.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-pymongo-debugsource-2.4.1-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pymongo / python-pymongo-debuginfo / etc");
}
