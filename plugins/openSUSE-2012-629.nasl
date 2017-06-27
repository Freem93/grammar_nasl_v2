#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-629.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74763);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id("CVE-2012-3955");

  script_name(english:"openSUSE Security Update : dhcp (openSUSE-SU-2012:1234-1)");
  script_summary(english:"Check for the openSUSE-2012-629 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to ISC dhcp-4.2.4-P2 release, providing a
    security fix for an issue with the use of lease times
    was found and fixed. Making certain changes to the end
    time of an IPv6 lease could cause the server to abort.
    Thanks to Glen Eustace of Massey University, New Zealand
    for finding this issue. ([ISC-Bugs #30281], CVE:
    CVE-2012-3955, bnc#780167)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780167"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"dhcp-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-client-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-client-debuginfo-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-debuginfo-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-debugsource-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-devel-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-relay-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-relay-debuginfo-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-server-4.2.4.P2-0.1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"dhcp-server-debuginfo-4.2.4.P2-0.1.4.1") ) flag++;

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
