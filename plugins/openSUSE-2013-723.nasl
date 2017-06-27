#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-723.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75154);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/15 14:55:53 $");

  script_cve_id("CVE-2012-4412", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-2207", "CVE-2013-4237", "CVE-2013-4332");
  script_osvdb_id(89747, 92038, 96318, 97246, 97247, 97248, 98105);

  script_name(english:"openSUSE Security Update : glibc (openSUSE-SU-2013:1510-1)");
  script_summary(english:"Check for the openSUSE-2013-723 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues in glibc :

  - CVE-2012-4412: glibc: buffer overflow in strcoll

  - CVE-2013-0242: glibc: DoS due to a buffer overrun in
    regexp matcher by processing multibyte characters

  - CVE-2013-1914: glibc: stack overflow in getaddrinfo()
    sorting

  - CVE-2013-2207: glibc: pt_chown tricked into granting
    access to another users pseudo-terminal

  - CVE-2013-4237: glibc: Buffer overwrite - NAME_MAX not
    enforced by readdir_r()

  - bnc#805054: man 1 locale mentions non-existent file

  - bnc#813306: glibc 2.17 fprintf(stderr, ...) triggers
    write of undefined values if stderr is closed

  - bnc#819383: pldd a process multiple times can freeze the
    process

  - bnc#819524: nscd segfault

  - bnc#824046: glibc: blacklist code in bindresvport
    doesn't release lock, results in double-lock

  - bnc#839870: glibc: three integer overflows in memory
    allocator

  - ARM: Support loading unmarked objects from cache"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839870"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"glibc-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-debugsource-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-devel-static-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-extra-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-extra-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-html-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-i18ndata-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-info-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-locale-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-locale-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-obsolete-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-obsolete-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-profile-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"glibc-utils-debugsource-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nscd-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nscd-debuginfo-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-locale-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-profile-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-utils-32bit-2.17-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.17-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
