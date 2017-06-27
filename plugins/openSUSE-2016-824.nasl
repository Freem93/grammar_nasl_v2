#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-824.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91944);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-5261", "CVE-2016-0749", "CVE-2016-2150");

  script_name(english:"openSUSE Security Update : spice (openSUSE-2016-824)");
  script_summary(english:"Check for the openSUSE-2016-824 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"spice was updated to fix two security issues.

These security issues were fixed :

  - CVE-2016-2150: SPICE allowed local guest OS users to
    read from or write to arbitrary host memory locations
    via crafted primary surface parameters, a similar issue
    to CVE-2015-5261 (boo#982385).

  - CVE-2016-0749: The smartcard interaction in SPICE
    allowed remote attackers to cause a denial of service
    (QEMU-KVM process crash) or possibly execute arbitrary
    code via vectors related to connecting to a guest VM,
    which triggers a heap-based buffer overflow
    (boo#982385)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982386"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libspice-server-devel-0.12.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libspice-server1-0.12.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libspice-server1-debuginfo-0.12.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-client-0.12.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-client-debuginfo-0.12.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"spice-debugsource-0.12.5-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libspice-server-devel / libspice-server1 / etc");
}
