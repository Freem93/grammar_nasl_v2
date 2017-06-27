#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1501.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96063);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id("CVE-2015-8400");

  script_name(english:"openSUSE Security Update : shellinabox (openSUSE-2016-1501)");
  script_summary(english:"Check for the openSUSE-2016-1501 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"shellinabox was updated to version 2.20 to fix the following security
issues :

  - It was possible to fallback to the HTTP protocol even
    when configured for HTTPS. (CVE-2015-8400, boo#957748)

  - Disable secure client-initiated renegotiation

  - Set SSL options for increased security (disable SSLv2,
    SSLv3)

  - Protection against large HTTP requests

non security fixes :

  - Includes some MSIE and iOS rendering fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957748"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shellinabox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shellinabox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shellinabox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shellinabox-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"shellinabox-2.20-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"shellinabox-debuginfo-2.20-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"shellinabox-debugsource-2.20-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"shellinabox-2.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"shellinabox-debuginfo-2.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"shellinabox-debugsource-2.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"shellinabox-2.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"shellinabox-debuginfo-2.20-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"shellinabox-debugsource-2.20-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shellinabox / shellinabox-debuginfo / shellinabox-debugsource");
}
