#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-181.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96918);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2016-9962");

  script_name(english:"openSUSE Security Update : containerd / docker / runc (openSUSE-2017-181)");
  script_summary(english:"Check for the openSUSE-2017-181 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for

  - containerd,

  - docker to version 1.12.6 and

  - runc fixes several issues.

This security issues was fixed :

  - CVE-2016-9962: container escape vulnerability
    (bsc#1012568).

Thsese non-security issues were fixed :

  - boo#1019251: Add a delay when starting docker service 

  - Fixed bash-completion

  - boo#1015661: add the /usr/bin/docker-run symlink 

For additional details please see the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected containerd / docker / runc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"containerd-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-ctr-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-ctr-debuginfo-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-debuginfo-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-debugsource-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"containerd-test-0.2.5+gitr569_2a5e70c-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-bash-completion-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"docker-zsh-completion-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-0.1.1+gitr2819_50a19c6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-debuginfo-0.1.1+gitr2819_50a19c6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-debugsource-0.1.1+gitr2819_50a19c6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"runc-test-0.1.1+gitr2819_50a19c6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-debuginfo-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-debugsource-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-test-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"docker-test-debuginfo-1.12.6-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"containerd-test-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"docker-bash-completion-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"docker-zsh-completion-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"runc-test-0.1.1+gitr2819_50a19c6-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-ctr-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-ctr-debuginfo-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-debuginfo-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"containerd-debugsource-0.2.5+gitr569_2a5e70c-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-debuginfo-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-debugsource-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-test-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"docker-test-debuginfo-1.12.6-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-0.1.1+gitr2819_50a19c6-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-debuginfo-0.1.1+gitr2819_50a19c6-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"runc-debugsource-0.1.1+gitr2819_50a19c6-8.1") ) flag++;

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
