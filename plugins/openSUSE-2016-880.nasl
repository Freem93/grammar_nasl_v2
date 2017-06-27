#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-880.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92449);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/04/03 15:09:39 $");

  script_cve_id("CVE-2016-5387");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2016-880) (httpoxy)");
  script_summary(english:"Check for the openSUSE-2016-880 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 fixes the following issues :

  - It used to be possible to set an arbitrary $HTTP_PROXY
    environment variable for request handlers -- like CGI
    scripts -- by including a specially crafted HTTP header
    in the request (CVE-2016-5387). As a result, these
    server components would potentially direct all their
    outgoing HTTP traffic through a malicious proxy server.
    This patch fixes the issue: the updated Apache server
    ignores such HTTP headers and never sets $HTTP_PROXY for
    sub-processes (unless a value has been explicitly
    configured by the administrator in the configuration
    file). (bsc#988488)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"apache2-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debuginfo-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debugsource-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-devel-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-debuginfo-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-example-pages-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-debuginfo-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-debuginfo-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-debuginfo-2.4.10-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-debuginfo-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-debugsource-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-devel-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-event-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-event-debuginfo-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-example-pages-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-prefork-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-prefork-debuginfo-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-utils-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-utils-debuginfo-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-worker-2.4.16-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-worker-debuginfo-2.4.16-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
