#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-360.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74662);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2012-1013");
  script_osvdb_id(82650);

  script_name(english:"openSUSE Security Update : krb5 (openSUSE-SU-2012:0834-1)");
  script_summary(english:"Check for the openSUSE-2012-360 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixing CVE-2012-1013 (krb5 kadmind denial of service via NULL pointer
dereference)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765485"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"krb5-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-client-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-client-debuginfo-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-debuginfo-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-debugsource-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-devel-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-plugin-kdb-ldap-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-plugin-kdb-ldap-debuginfo-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-plugin-preauth-pkinit-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-server-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"krb5-server-debuginfo-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"krb5-32bit-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"krb5-devel-32bit-1.8.3-16.49.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-client-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-client-debuginfo-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-debuginfo-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-debugsource-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-devel-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-kdb-ldap-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-kdb-ldap-debuginfo-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-preauth-pkinit-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-server-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"krb5-server-debuginfo-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-32bit-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.9.1-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"krb5-devel-32bit-1.9.1-24.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
