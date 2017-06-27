#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-657.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86392);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2013-4282", "CVE-2015-3247", "CVE-2015-5260", "CVE-2015-5261");

  script_name(english:"openSUSE Security Update : spice (openSUSE-2015-657)");
  script_summary(english:"Check for the openSUSE-2015-657 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Spice was updated to fix four security issues.

The following vulnerabilities were fixed :

  - CVE-2015-3247: heap corruption in the spice server
    (bsc#944460)

  - CVE-2015-5261: Guest could have accessed host memory
    using crafted images (bsc#948976)

  - CVE-2015-5260: Insufficient validation of surface_id
    parameter could have caused a crash (bsc#944460)

  - CVE-2013-4282: Buffer overflow in password handling
    (bsc#848279)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=848279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=948976"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-server1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libspice-server-devel-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libspice-server1-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libspice-server1-debuginfo-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"spice-client-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"spice-client-debuginfo-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"spice-debugsource-0.12.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libspice-server-devel-0.12.4-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libspice-server1-0.12.4-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libspice-server1-debuginfo-0.12.4-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"spice-client-0.12.4-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"spice-client-debuginfo-0.12.4-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"spice-debugsource-0.12.4-4.6.1") ) flag++;

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
