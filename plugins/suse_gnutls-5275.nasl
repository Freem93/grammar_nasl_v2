#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gnutls-5275.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34214);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");

  script_name(english:"openSUSE 10 Security Update : gnutls (gnutls-5275)");
  script_summary(english:"Check for the gnutls-5275 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple issues have been fixed in gnutls: CVE-2008-1948
(GNUTLS-SA-2008-1-1), CVE-2008-1949 (GNUTLS-SA-2008-1-2) and
CVE-2008-1950 (GNUTLS-SA-2008-1-3) have been assigned to this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/16");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"gnutls-1.4.4-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"gnutls-devel-1.4.4-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"gnutls-32bit-1.4.4-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"gnutls-devel-32bit-1.4.4-19") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"gnutls-1.6.1-36.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"gnutls-devel-1.6.1-36.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"gnutls-32bit-1.6.1-36.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"gnutls-devel-32bit-1.6.1-36.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");
}
