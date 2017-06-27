#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-2524.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94093);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id("CVE-2016-7044", "CVE-2016-7045", "CVE-2016-7553");

  script_name(english:"openSUSE Security Update : irssi (openSUSE-2016-2524)");
  script_summary(english:"Check for the openSUSE-2016-2524 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IRC client irssi was updated to 0.8.20, fixing various bugs and
security issues.

  - CVE-2016-7044: The unformat_24bit_color function in the
    format parsing code in Irssi, when compiled with
    true-color enabled, allowed remote attackers to cause a
    denial of service (heap corruption and crash) via an
    incomplete 24bit color code.

  - CVE-2016-7045: The format_send_to_gui function in the
    format parsing code in Irssi allowed remote attackers to
    cause a denial of service (heap corruption and crash)
    via vectors involving the length of a string.

See https://irssi.org/security/irssi_sa_2016.txt for more details.

  - CVE-2016-7553: A information disclosure vulnerability in
    irssi buf.pl

See https://irssi.org/2016/09/22/buf.pl-update/ for more information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://irssi.org/2016/09/22/buf.pl-update/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://irssi.org/security/irssi_sa_2016.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irssi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/17");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"irssi-0.8.20-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"irssi-debuginfo-0.8.20-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"irssi-debugsource-0.8.20-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"irssi-devel-0.8.20-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-0.8.20-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debuginfo-0.8.20-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debugsource-0.8.20-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-devel-0.8.20-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi / irssi-debuginfo / irssi-debugsource / irssi-devel");
}
