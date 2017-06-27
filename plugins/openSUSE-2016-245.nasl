#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-245.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88920);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-2774");

  script_name(english:"openSUSE Security Update : erlang (openSUSE-2016-245)");
  script_summary(english:"Check for the openSUSE-2016-245 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for erlang fixes the following issues :

  - CVE-2015-2774: Erlang/OTP was vulnerable to Poodle in
    its TLS-1.0 implementation - removed default support for
    SSL 3.0 and added padding check for TLS 1.0 (boo#924915)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924915"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected erlang packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugger-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-epmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-epmd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-et-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-gs-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-jinterface-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-observer-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-reltool-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"erlang-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-debugger-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-debugger-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-debuginfo-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-debugsource-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-dialyzer-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-dialyzer-debuginfo-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-dialyzer-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-epmd-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-epmd-debuginfo-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-et-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-et-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-gs-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-gs-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-jinterface-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-jinterface-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-observer-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-observer-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-reltool-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-reltool-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-src-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-wx-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-wx-debuginfo-17.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"erlang-wx-src-17.1-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "erlang / erlang-debugger / erlang-debugger-src / erlang-debuginfo / etc");
}
