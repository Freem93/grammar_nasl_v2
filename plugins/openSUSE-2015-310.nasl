#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-310.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82845);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/04 14:10:50 $");

  script_cve_id("CVE-2015-3026");

  script_name(english:"openSUSE Security Update : icecast (openSUSE-2015-310)");
  script_summary(english:"Check for the openSUSE-2015-310 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The streaming server icecast was updated to fix a remote denial of
service vulnerability.

A remote attacker could crash icecast and cause denial of service when
URL Auth is configured and used with stream_auth without credentials
(bnc#926402 CVE-2015-3026)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926402"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icecast packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icecast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icecast-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icecast-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");
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

if ( rpm_check(release:"SUSE13.1", reference:"icecast-2.3.3-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icecast-debuginfo-2.3.3-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icecast-debugsource-2.3.3-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icecast-2.4.0-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icecast-debuginfo-2.4.0-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"icecast-debugsource-2.4.0-2.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icecast / icecast-debuginfo / icecast-debugsource");
}
