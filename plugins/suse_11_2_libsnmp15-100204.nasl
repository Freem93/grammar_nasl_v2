#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libsnmp15-1922.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44403);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2008-6123");

  script_name(english:"openSUSE Security Update : libsnmp15 (libsnmp15-1922)");
  script_summary(english:"Check for the libsnmp15-1922 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of net-snmp fixes the following bugs :

  - truncated walk of hrSWRunPath (bnc#565586)

  - crash when 64-bit counters wrap (bnc#523553)

  - unknown host names in snmp traps (bnc#514333)

  - sensitive host information disclosure (bnc#475532,
    CVE-2008-6123)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=466805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=473328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=475532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=523553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=565586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsnmp15 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libsnmp15-5.4.2.1-11.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"net-snmp-5.4.2.1-11.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"net-snmp-devel-5.4.2.1-11.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"perl-SNMP-5.4.2.1-11.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"snmp-mibs-5.4.2.1-11.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libsnmp15-32bit-5.4.2.1-11.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
