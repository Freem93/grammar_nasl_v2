#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-302.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74958);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-2266");

  script_name(english:"openSUSE Security Update : dhcp (openSUSE-SU-2013:0620-1)");
  script_summary(english:"Check for the openSUSE-2013-302 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC DHCP was updated to ISC dhcp-4.2.5-P1 release, which contains
updated bind-9.8.4-P2 sources with removed regex.h check in configure
(bnc#811934, CVE-2013-2266).

Also: Changed spec make the bind export library build output visible.
Added dhcp6-server service template for SuSEfirewall2 (bnc#783002)
Update config.guess/sub for aarch64"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811934"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"dhcp-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-client-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-client-debuginfo-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-debuginfo-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-debugsource-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-devel-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-relay-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-relay-debuginfo-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-server-4.2.5.P1-0.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dhcp-server-debuginfo-4.2.5.P1-0.2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
