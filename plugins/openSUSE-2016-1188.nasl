#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1188.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94063);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/14 14:05:17 $");

  script_cve_id("CVE-2015-7696", "CVE-2015-7697");

  script_name(english:"openSUSE Security Update : unzip (openSUSE-2016-1188)");
  script_summary(english:"Check for the openSUSE-2016-1188 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for unzip fixes the following issues :

  - CVE-2015-7696: Specially crafted zip files with password
    protection could trigger a crash and lead to denial of
    service (bsc#950110)

  - CVE-2015-7697: Specially crafted zip files could trigger
    an endless loop and lead to denial of service
    (bsc#950111)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950111"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unzip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");
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

if ( rpm_check(release:"SUSE13.2", reference:"unzip-6.00-26.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-debuginfo-6.00-26.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-debugsource-6.00-26.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-6.00-26.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-debuginfo-6.00-26.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-debugsource-6.00-26.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unzip-rcc / unzip-rcc-debuginfo / unzip-rcc-debugsource / unzip / etc");
}
