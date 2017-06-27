#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-590.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91207);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2014-9773", "CVE-2016-4478");

  script_name(english:"openSUSE Security Update : atheme (openSUSE-2016-590)");
  script_summary(english:"Check for the openSUSE-2016-590 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for atheme fixes the following issues :

  - CVE-2016-4478: Under certain circumstances, a remote
    attacker could cause denial of service due to a buffer
    overflow in the XMLRPC response encoding code
    (boo#978170)

  - CVE-2014-9773: Remote attacker could change Atheme's
    behavior by registering/dropping certain accounts/nicks
    (boo#978170)

The version update to 7.2.6 also contains a number of upstream fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978170"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected atheme packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atheme-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atheme-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atheme-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libathemecore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libathemecore1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
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

if ( rpm_check(release:"SUSE13.2", reference:"atheme-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"atheme-debuginfo-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"atheme-debugsource-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"atheme-devel-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libathemecore1-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libathemecore1-debuginfo-7.2.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"atheme-7.2.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"atheme-debuginfo-7.2.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"atheme-debugsource-7.2.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"atheme-devel-7.2.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libathemecore1-7.2.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libathemecore1-debuginfo-7.2.6-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atheme / atheme-debuginfo / atheme-debugsource / atheme-devel / etc");
}
