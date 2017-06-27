#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-218.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81762);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/30 13:52:21 $");

  script_cve_id("CVE-2015-2157");

  script_name(english:"openSUSE Security Update : putty (openSUSE-2015-218)");
  script_summary(english:"Check for the openSUSE-2015-218 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SSH Terminal emulator putty was updated to the new upstream
release 0.64, fixing security issues and bugs :

Security fix: PuTTY no longer retains the private half of users' keys
in memory by mistake after authenticating with them. [bsc#920167]
(CVE-2015-2157)

New feature: Support for SSH connection sharing, so that multiple
instances of PuTTY to the same host can share a single SSH connection
instead of all having to log in independently.

Bug fix: IPv6 literals are handled sensibly throughout the suite, if
you enclose them in square brackets to prevent the colons being
mistaken for a :port suffix."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920167"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected putty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");
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

if ( rpm_check(release:"SUSE13.1", reference:"putty-0.64-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"putty-debuginfo-0.64-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"putty-debugsource-0.64-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-0.64-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-debuginfo-0.64-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-debugsource-0.64-4.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "putty / putty-debuginfo / putty-debugsource");
}
