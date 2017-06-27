#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-432.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84283);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/19 13:42:52 $");

  script_cve_id("CVE-2015-4171");

  script_name(english:"openSUSE Security Update : strongswan (openSUSE-2015-432)");
  script_summary(english:"Check for the openSUSE-2015-432 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"strongswan was updated to fix a rogue servers vulnerability, that may
enable rogue servers able to authenticate itself with certificate
issued by any CA the client trusts, to gain user credentials from a
client in certain IKEv2 setups (bsc#933591,CVE-2015-4171).

More information can be found on
https://www.strongswan.org/blog/2015/06/08/strongswan-vulnerability-%2
8cve-2015-4171%29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933591"
  );
  # https://www.strongswan.org/blog/2015/06/08/strongswan-vulnerability-%28cve-2015-4171%29.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4cda5a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected strongswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");
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

if ( rpm_check(release:"SUSE13.1", reference:"strongswan-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-debugsource-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-debuginfo-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-debuginfo-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-debuginfo-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-debuginfo-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-debuginfo-5.1.1-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-debugsource-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-debuginfo-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-debuginfo-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-debuginfo-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-debuginfo-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-5.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-debuginfo-5.1.3-4.11.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan / strongswan-debugsource / strongswan-ipsec / etc");
}
