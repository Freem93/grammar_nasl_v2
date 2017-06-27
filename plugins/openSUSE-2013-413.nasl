#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-413.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74994);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-2944");
  script_osvdb_id(92878);

  script_name(english:"openSUSE Security Update : strongswan (openSUSE-SU-2013:0775-1)");
  script_summary(english:"Check for the openSUSE-2013-413 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Applied upstream patch for security vulnerability
    discovered by Kevin Wojtysiak in ECDSA signature
    verification of the strongswan openssl plugin
    (bnc#815236, CVE-2013-2944)
    [0003-Check-return-value-of-ECDSA_Verify-correctly.patch
    ]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815236"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected strongswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ikev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ikev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ikev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ikev2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"strongswan-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-debugsource-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ikev1-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ikev1-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ikev2-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ikev2-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ipsec-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-ipsec-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-libs0-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-libs0-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-mysql-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-mysql-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-nm-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-nm-debuginfo-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-sqlite-4.6.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"strongswan-sqlite-debuginfo-4.6.4-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan / strongswan-debugsource / strongswan-ikev1 / etc");
}
