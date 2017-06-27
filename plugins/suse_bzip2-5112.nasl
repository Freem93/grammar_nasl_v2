#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update bzip2-5112.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32211);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:05 $");

  script_cve_id("CVE-2008-1372");

  script_name(english:"openSUSE 10 Security Update : bzip2 (bzip2-5112)");
  script_summary(english:"Check for the bzip2-5112 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Specially crafted files could crash the bzip2-decoder (CVE-2008-1372)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bzip2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbz2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbz2-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbz2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"bzip2-1.0.3-17.9") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"bzip2-32bit-1.0.3-17.9") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"bzip2-1.0.3-39.4") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"bzip2-32bit-1.0.3-39.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"bzip2-1.0.4-42.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libbz2-1-1.0.4-42.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libbz2-devel-1.0.4-42.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libbz2-1-32bit-1.0.4-42.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzip2 / bzip2-32bit / libbz2-1 / libbz2-1-32bit / libbz2-devel");
}
