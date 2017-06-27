#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-505.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84996);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/27 13:18:25 $");

  script_cve_id("CVE-2015-1868", "CVE-2015-5470");

  script_name(english:"openSUSE Security Update : pdns / pdns-recursor (openSUSE-2015-505)");
  script_summary(english:"Check for the openSUSE-2015-505 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pdns, pdns-recursor were updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-1868: The label decompression functionality in
    PowerDNS Recursor 3.5.x, 3.6.x before 3.6.3, and 3.7.x
    before 3.7.2 and Authoritative (Auth) Server 3.2.x,
    3.3.x before 3.3.2, and 3.4.x before 3.4.4 allowed
    remote attackers to cause a denial of service (CPU
    consumption or crash) via a request with a name that
    refers to itself (bsc#927569).

  - CVE-2015-5470: Complete fix for CVE-2015-1868
    (bsc#927569)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927569"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pdns / pdns-recursor packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
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

if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-3.6.2-8.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-debuginfo-3.6.2-8.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pdns-recursor-debugsource-3.6.2-8.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-ldap-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-ldap-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-lua-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-lua-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mydns-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mydns-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mysql-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-mysql-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-postgresql-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-postgresql-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-sqlite3-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-backend-sqlite3-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-debuginfo-3.3.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pdns-debugsource-3.3.1-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns-recursor / pdns-recursor-debuginfo / pdns-recursor-debugsource / etc");
}
