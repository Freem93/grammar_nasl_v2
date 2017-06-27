#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-500.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77289);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/23 10:40:03 $");

  script_cve_id("CVE-2014-3564");

  script_name(english:"openSUSE Security Update : gpgme (openSUSE-SU-2014:1039-1)");
  script_summary(english:"Check for the openSUSE-2014-500 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This gpgme update to version 1.4.4 fixes the following security and
non i security issues :

  - Fixed possible overflow in gpgsm and uiserver engines.
    (CVE-2014-3564, bnc#890123)

  - Fixed possibled segv in gpgme_op_card_edit.

  - Fixed minor memleaks and possible zombie processes.

  - Fixed prototype inconsistencies and void pointer
    arithmetic."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=890123"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gpgme packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpgme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gpgme-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgpgme-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgpgme11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgpgme11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgpgme11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgpgme11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/21");
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

if ( rpm_check(release:"SUSE12.3", reference:"gpgme-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"gpgme-debugsource-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgpgme-devel-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgpgme11-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgpgme11-debuginfo-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgpgme11-32bit-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgpgme11-debuginfo-32bit-1.3.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gpgme-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gpgme-debugsource-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgpgme-devel-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgpgme11-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgpgme11-debuginfo-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgpgme11-32bit-1.4.4-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgpgme11-debuginfo-32bit-1.4.4-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpgme / gpgme-debugsource / libgpgme-devel / libgpgme11 / etc");
}
