#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1376.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95531);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2016-7035", "CVE-2016-7797");

  script_name(english:"openSUSE Security Update : pacemaker (openSUSE-2016-1376)");
  script_summary(english:"Check for the openSUSE-2016-1376 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pacemaker fixes the following issues :

Security issues fixed :

  - CVE-2016-7797: Notify other clients of a new connection
    only if the handshake has completed (bsc#967388,
    bsc#1002767).

  - CVE-2016-7035: Fixed improper IPC guarding in pacemaker
    (bsc#1007433).

Bug fixes :

  - bsc#1003565: crmd: Record pending operations in the CIB
    before they are performed

  - bsc#1000743: pengine: Do not fence a maintenance node if
    it shuts down cleanly

  - bsc#987348: ping: Avoid temporary files for fping check

  - bsc#986644: libcrmcommon: report errors consistently
    when waiting for data on connection

  - bsc#986644: remote: Correctly calculate the remaining
    timeouts when receiving messages

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987348"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libpacemaker-devel-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpacemaker3-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpacemaker3-debuginfo-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-cli-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-cli-debuginfo-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-cts-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-cts-debuginfo-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-debuginfo-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-debugsource-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-remote-1.1.15-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pacemaker-remote-debuginfo-1.1.15-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpacemaker-devel / libpacemaker3 / libpacemaker3-debuginfo / etc");
}
