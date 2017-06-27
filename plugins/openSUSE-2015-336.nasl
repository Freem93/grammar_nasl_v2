#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-336.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83159);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/06 14:51:23 $");

  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2015-336)");
  script_summary(english:"Check for the openSUSE-2015-336 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"curl was updated to fix four security issues.

The following vulnerabilities were fixed :

  - CVE-2015-3143: curl could re-use NTML authenticateds
    connections

  - CVE-2015-3144: curl could access memory out of bounds
    with zero length host names

  - CVE-2015-3145: curl cookie parser could access memory
    out of boundary

  - CVE-2015-3148: curl could treat Negotiate as not
    connection-oriented"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927746"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");
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

if ( rpm_check(release:"SUSE13.1", reference:"curl-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"curl-debuginfo-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"curl-debugsource-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl-devel-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl4-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl4-debuginfo-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcurl4-32bit-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.42.0-2.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-debuginfo-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-debugsource-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl-devel-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl4-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl4-debuginfo-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcurl4-32bit-7.42.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.42.0-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / libcurl-devel / etc");
}
