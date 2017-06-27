#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-474.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76958);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2013-5211");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-2014-474)");
  script_summary(english:"Check for the openSUSE-2014-474 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The NTP time service could be used for remote denial of service
amplification attacks.

This issue can be fixed by the administrator as we described in our
security advisory SUSE-SA:2014:001
http://lists.opensuse.org/opensuse-security-announce/2014-01/msg00005.
html

and on http://support.novell.com/security/cve/CVE-2013-5211.html

This update now also replaces the default ntp.conf template to fix
this problem.

Please note that if you have touched or modified ntp.conf yourself, it
will not be automatically fixed, you need to merge the changes
manually as described."
  );
  # http://lists.opensuse.org/opensuse-security-announce/2014-01/msg00005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf39e777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857195"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"ntp-4.2.6p5-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ntp-debuginfo-4.2.6p5-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ntp-debugsource-4.2.6p5-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-4.2.6p5-15.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-debuginfo-4.2.6p5-15.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-debugsource-4.2.6p5-15.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
