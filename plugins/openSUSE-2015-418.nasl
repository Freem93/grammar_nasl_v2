#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-418.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84184);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/29 18:58:19 $");

  script_cve_id("CVE-2012-5519", "CVE-2015-1158", "CVE-2015-1159");

  script_name(english:"openSUSE Security Update : cups (openSUSE-2015-418)");
  script_summary(english:"Check for the openSUSE-2015-418 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues :

  - CVE-2015-1158 and CVE-2015-1159 fixes a possible
    privilege escalation via cross-site scripting and bad
    print job submission used to replace cupsd.conf on
    server (CUPS STR#4609 CERT-VU-810572 CVE-2015-1158
    CVE-2015-1159 bugzilla.suse.com bsc#924208). In general
    it is crucial to limit access to CUPS to trustworthy
    users who do not misuse their permission to submit print
    jobs which means to upload arbitrary data onto the CUPS
    server, see
    https://en.opensuse.org/SDB:CUPS_and_SANE_Firewall_setti
    ngs and cf. the entries about CVE-2012-5519 below."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://en.opensuse.org/SDB:CUPS_and_SANE_Firewall_settings"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cups-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-client-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-client-debuginfo-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-ddk-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-ddk-debuginfo-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-debuginfo-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-debugsource-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-devel-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-libs-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cups-libs-debuginfo-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"cups-libs-32bit-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"cups-libs-debuginfo-32bit-1.5.4-12.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-client-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-client-debuginfo-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-ddk-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-ddk-debuginfo-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-debuginfo-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-debugsource-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-devel-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-libs-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-libs-debuginfo-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"cups-libs-32bit-1.5.4-21.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"cups-libs-debuginfo-32bit-1.5.4-21.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-client-debuginfo / cups-ddk / etc");
}
