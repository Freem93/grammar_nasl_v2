#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libwsman-devel-157.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40053);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/22 15:04:20 $");

  script_cve_id("CVE-2008-2233", "CVE-2008-2234");
  script_xref(name:"IAVB", value:"2008-B-0064");

  script_name(english:"openSUSE Security Update : libwsman-devel (libwsman-devel-157)");
  script_summary(english:"Check for the libwsman-devel-157 patch");

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
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=373693"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwsman-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsman1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"libwsman-devel-2.0.0-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libwsman1-2.0.0-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"openwsman-client-2.0.0-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"openwsman-python-2.0.0-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"openwsman-ruby-2.0.0-3.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"openwsman-server-2.0.0-3.3") ) flag++;

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
