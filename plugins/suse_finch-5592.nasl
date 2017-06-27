#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update finch-5592.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34199);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2008-2927", "CVE-2008-2955", "CVE-2008-3532");

  script_name(english:"openSUSE 10 Security Update : finch (finch-5592)");
  script_summary(english:"Check for the finch-5592 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - specially crafted MSN SLP messages could cause an
    integer overflow in pidgin. Attackers could potentially
    exploit that to execute arbitrary code (CVE-2008-2927).

  - overly long file names in MSN file transfers could crash
    pidgin (CVE-2008-2955).

  - SSL certifcates were not verfied. Therefore piding
    didn't notice faked certificates (CVE-2008-3532)

Additionally a problem was fixed that prevented gaim clients from
connecting to the ICQ network after a server change on July 1st 2008."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"finch-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"finch-devel-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libpurple-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libpurple-devel-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libpurple-meanwhile-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libpurple-mono-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pidgin-2.3.1-26.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pidgin-devel-2.3.1-26.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / etc");
}
