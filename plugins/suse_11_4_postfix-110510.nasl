#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update postfix-4524.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75997);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1720");

  script_name(english:"openSUSE Security Update : postfix (openSUSE-SU-2011:0476-1)");
  script_summary(english:"Check for the postfix-4524 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Remote attackers could potentially exploit a memory corruption issue
in postfix' SASL implementation to execute arbitrary code
(CVE-2011-1720)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-05/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689021"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"postfix-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-debuginfo-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-debugsource-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-devel-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-mysql-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-mysql-debuginfo-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-postgresql-2.7.2-13.16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"postfix-postgresql-debuginfo-2.7.2-13.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix");
}
