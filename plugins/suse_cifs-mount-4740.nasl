#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cifs-mount-4740.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28370);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:06:05 $");

  script_cve_id("CVE-2007-4572", "CVE-2007-5398");

  script_name(english:"openSUSE 10 Security Update : cifs-mount (cifs-mount-4740)");
  script_summary(english:"Check for the cifs-mount-4740 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes two buffer overflows in nmbd (CVE-2007-4572,
CVE-2007-5398). Remote attackers could potentially exploit them to
execute arbitrary code.

The updated packages additionally contain fixes for numerous other
defects. Please refer to the package changelog for details."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-mount packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-vscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.1", reference:"cifs-mount-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ldapsmb-1.34a-18.32") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libmsrpc-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libmsrpc-devel-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libsmbclient-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libsmbclient-devel-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-client-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-pdb-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-python-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-vscan-0.3.6b-42.63") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"samba-winbind-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-32bit-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.36") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"cifs-mount-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ldapsmb-1.34b-27.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-devel-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-devel-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-client-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-krb-printing-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-pdb-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-python-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-vscan-0.3.6b-98.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-winbind-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-32bit-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-client-32bit-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.23d-19.10") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"cifs-mount-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ldapsmb-1.34b-110.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libmsrpc-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libmsrpc-devel-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libsmbclient-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libsmbclient-devel-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libsmbsharemodes-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libsmbsharemodes-devel-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-client-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-devel-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-krb-printing-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-python-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-vscan-0.3.6b-181.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"samba-winbind-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"samba-32bit-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"samba-client-32bit-3.0.26a-3.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.26a-3.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-mount / ldapsmb / libmsrpc / libmsrpc-devel / libsmbclient / etc");
}
