#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-641.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79107);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/17 12:13:04 $");

  script_cve_id("CVE-2014-7202", "CVE-2014-7203");

  script_name(english:"openSUSE Security Update : zeromq (openSUSE-SU-2014:1381-1)");
  script_summary(english:"Check for the openSUSE-2014-641 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This udpate for zeromq fixes the following non-security and
security-issues: Update to version 4.0.4, for a detailed description
see /usr/share/doc/packages/zeromq-devel/NEWS

  - Add libsodium dep for testsuite where possible

  - Version bump to 4.0.5 fixes bnc#898917 CVE-2014-7202 and
    CVE-2014-7203 :

  - Fixed CURVE mechanism does not verify short term nonces.

  - Fixed stream_engine is vulnerable to downgrade attacks.

  - Fixed assertion failure for WSAENOTSOCK on Windows.

  - Fixed race condition while connecting inproc sockets.

  - Fixed bump so library number to 4.0.0

  - Fixed assertion failed: !more (fq.cpp:99) after many ZAP
    requests.

  - Fixed lost first part of message over inproc://.

  - Fixed keep-alive on Windows.

  - Enable tests.

  - Move to 'download_files' source service which is in
    better shap and easier to use"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898917"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zeromq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzmq4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zeromq-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
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

if ( rpm_check(release:"SUSE12.3", reference:"libzmq4-4.0.5-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libzmq4-debuginfo-4.0.5-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"zeromq-debugsource-4.0.5-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"zeromq-devel-4.0.5-2.4.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzmq4-4.0.5-4.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libzmq4-debuginfo-4.0.5-4.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"zeromq-debugsource-4.0.5-4.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"zeromq-devel-4.0.5-4.4.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zeromq");
}
