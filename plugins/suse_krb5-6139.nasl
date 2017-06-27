#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update krb5-6139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(36122);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");

  script_name(english:"openSUSE 10 Security Update : krb5 (krb5-6139)");
  script_summary(english:"Check for the krb5-6139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Clients sending negotiation requests with invalid flags could crash
the kerberos server (CVE-2009-0845).

GSS-API clients could crash when reading from an invalid address space
(CVE-2009-0844).

Invalid length checks could crash applications using the kerberos
ASN.1 parser (CVE-2009-0847).

Under certain circumstances the ASN.1 parser could free an
uninitialized pointer which could crash a kerberos server or even lead
to execution of arbitrary code (CVE-2009-0846)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-apps-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-apps-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"krb5-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"krb5-apps-clients-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"krb5-apps-servers-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"krb5-client-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"krb5-devel-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"krb5-server-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"krb5-32bit-1.6.2-22.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"krb5-devel-32bit-1.6.2-22.9") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
