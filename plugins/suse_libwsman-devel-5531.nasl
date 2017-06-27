#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libwsman-devel-5531.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34025);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2008-2233", "CVE-2008-2234");
  script_xref(name:"IAVB", value:"2008-B-0064");

  script_name(english:"openSUSE 10 Security Update : libwsman-devel (libwsman-devel-5531)");
  script_summary(english:"Check for the libwsman-devel-5531 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of openwsman fixes several security vulnerabilities found
by the SuSE Security-Team :

  - remote buffer overflows while decoding the HTTP basic
    authentication header (CVE-2008-2234)

  - a possible SSL session replay attack affecting the
    client (depending on the configuration) (CVE-2008-2233)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwsman-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/22");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE10.3", reference:"openwsman-1.2.0-14.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openwsman-client-1.2.0-14.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openwsman-devel-1.2.0-14.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openwsman-server-1.2.0-14.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openwsman");
}
