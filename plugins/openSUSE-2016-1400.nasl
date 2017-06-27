#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1400.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95554);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/12/06 14:24:42 $");

  script_cve_id("CVE-2016-8867");

  script_name(english:"openSUSE Security Update : containerd / docker / runc (openSUSE-2016-1400)");
  script_summary(english:"Check for the openSUSE-2016-1400 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for containerd, docker, runc fixes the following issues :

Security issues fixed :

  - CVE-2016-8867: Fix ambient capability usage in
    containers (bsc#1007249).

Bugfixes :

  - boo#1006368: Fixed broken docker/containerd installation
    when installed by SuSE Studio in an appliance.

  - boo#1004490: Update docker to 1.12.2

  - boo#977394: Fix go version to 1.5.

  - boo#999582: Change the internal mountpoint name to not
    use ':' as that character can be considered a special
    character by other tools.

  - Update docker to 1.12.3

  - https://github.com/docker/docker/releases/tag/v1.12.3
This update changes the runc versioning scheme to prevent version downgrades
    (boo#1009961)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/docker/docker/releases/tag/v1.12.3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected containerd / docker / runc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"containerd-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-ctr-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-ctr-debuginfo-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-debuginfo-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-debugsource-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-test-0.2.4+gitr565_0366d7e-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-bash-completion-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-zsh-completion-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-0.1.1+gitr2816_02f8fa7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-debuginfo-0.1.1+gitr2816_02f8fa7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-debugsource-0.1.1+gitr2816_02f8fa7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-test-0.1.1+gitr2816_02f8fa7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-debuginfo-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-debugsource-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-test-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-test-debuginfo-1.12.3-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"containerd-test-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"docker-bash-completion-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"docker-zsh-completion-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"runc-test-0.1.1+gitr2816_02f8fa7-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-ctr-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-ctr-debuginfo-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-debuginfo-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-debugsource-0.2.4+gitr565_0366d7e-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-debuginfo-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-debugsource-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-test-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-test-debuginfo-1.12.3-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-0.1.1+gitr2816_02f8fa7-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-debuginfo-0.1.1+gitr2816_02f8fa7-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-debugsource-0.1.1+gitr2816_02f8fa7-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-ctr-debuginfo / etc");
}
