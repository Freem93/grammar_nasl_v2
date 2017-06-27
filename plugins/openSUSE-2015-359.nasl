#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-359.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83398);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/13 14:37:10 $");

  script_cve_id("CVE-2015-3294");

  script_name(english:"openSUSE Security Update : dnsmasq (openSUSE-2015-359)");
  script_summary(english:"Check for the openSUSE-2015-359 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The DNS server dnsmasq was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-3294: A remote unauthenticated attacker could
    have caused a denial of service (DoS) or read heap
    memory, potentially disclosing information such as
    performed DNS queries or encryption keys. (bsc#928867)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"dnsmasq-2.65-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dnsmasq-debuginfo-2.65-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dnsmasq-debugsource-2.65-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dnsmasq-utils-2.65-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dnsmasq-utils-debuginfo-2.65-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dnsmasq-2.71-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dnsmasq-debuginfo-2.71-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dnsmasq-debugsource-2.71-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dnsmasq-utils-2.71-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dnsmasq-utils-debuginfo-2.71-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-debuginfo / dnsmasq-debugsource / dnsmasq-utils / etc");
}
