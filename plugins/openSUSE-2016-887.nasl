#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-887.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92506);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/18 14:03:58 $");

  script_cve_id("CVE-2016-2774");
  script_xref(name:"IAVB", value:"2016-B-0044");

  script_name(english:"openSUSE Security Update : dhcp (openSUSE-2016-887)");
  script_summary(english:"Check for the openSUSE-2016-887 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dhcp fixes the following issues :

Security issue fixed :

  - CVE-2016-2774: Fixed a denial of service attack against
    the DHCP server over the OMAPI TCP socket, which could
    be used by network adjacent attackers to make the DHCP
    server non-functional (bsc#969820).

Non security issues fixed :

  - Rename freeaddrinfo(), getaddrinfo() and getnameinfo()
    in the internal libirs library that does not consider
    /etc/hosts and /etc/nsswitch.conf to use irs_ prefix.
    This prevents name conflicts which would result in
    overriding standard glibc functions used by libldap.
    (bsc#972907)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972907"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-relay-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.1", reference:"dhcp-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-client-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-client-debuginfo-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-debuginfo-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-debugsource-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-devel-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-relay-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-relay-debuginfo-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-server-4.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dhcp-server-debuginfo-4.3.3-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp / dhcp-client / dhcp-client-debuginfo / dhcp-debuginfo / etc");
}
