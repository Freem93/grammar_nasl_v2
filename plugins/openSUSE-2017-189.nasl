#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96942);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/02 14:39:40 $");

  script_cve_id("CVE-2016-6354");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-2017-189)");
  script_summary(english:"Check for the openSUSE-2017-189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for SeaMonkey to version 2.46 fixes security issues and
bugs.

The following vulnerabilities were fixed :

  - Fix all Gecko related security issues between 43.0.1 and
    49.0.2

  - CVE-2016-6354: buffer overrun in flex (boo#990856)

The following non-security changes are included :

  - improve recognition of LANGUAGE env variable
    (boo#1017174)

  - improve TLS compatibility with certain websites
    (boo#1021636)

  - SeaMonkey now requires NSPR 4.12 and NSS 3.25

  - based on Gecko 49.0.2

  - Chatzilla and DOM Inspector were disabled"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debuginfo-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debugsource-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-common-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-other-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"seamonkey-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"seamonkey-debuginfo-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"seamonkey-debugsource-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"seamonkey-translations-common-2.46-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"seamonkey-translations-other-2.46-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}
