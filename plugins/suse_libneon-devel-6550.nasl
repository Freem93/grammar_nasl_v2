#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libneon-devel-6550.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42324);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-2408", "CVE-2009-2473");

  script_name(english:"openSUSE 10 Security Update : libneon-devel (libneon-devel-6550)");
  script_summary(english:"Check for the libneon-devel-6550 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"neon did not properly handle embedded NUL characters in X.509
certificates when comparing host names. Attackers could exploit that
to spoof SSL servers (CVE-2009-2408).

Specially crafted XML documents that contain a large number of nested
entity references could cause neon to consume large amounts of CPU and
memory (CVE-2009-2473)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libneon-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neon-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neon-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/30");
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

if ( rpm_check(release:"SUSE10.3", reference:"neon-0.26.4-17.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"neon-devel-0.26.4-17.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"neon-32bit-0.26.4-17.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "neon / neon-32bit / neon-devel");
}
