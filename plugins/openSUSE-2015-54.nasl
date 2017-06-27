#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-54.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80988);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/26 14:49:32 $");

  script_cve_id("CVE-2014-9221");

  script_name(english:"openSUSE Security Update : strongswan (openSUSE-SU-2015:0114-1)");
  script_summary(english:"Check for the openSUSE-2015-54 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - denial-of-service vulnerability, which can be triggered
    by an IKEv2 Key Exchange payload, that contains the
    Diffie-Hellman group 1025 (bsc#910491,CVE-2014-9221).

  - Applied an upstream patch reverting to store algorithms
    in the registration order again as ordering them by
    identifier caused weaker algorithms to be proposed first
    by default (bsc#897512)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910491"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected strongswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");
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

if ( rpm_check(release:"SUSE13.1", reference:"strongswan-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-debugsource-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-debuginfo-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-debuginfo-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-debuginfo-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-debuginfo-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-debuginfo-5.1.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-debugsource-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-debuginfo-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-debuginfo-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-debuginfo-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-debuginfo-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-5.1.3-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-debuginfo-5.1.3-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan / strongswan-debugsource / strongswan-ipsec / etc");
}
