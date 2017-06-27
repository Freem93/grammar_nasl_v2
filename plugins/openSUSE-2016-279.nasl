#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-279.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89017);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-8605");

  script_name(english:"openSUSE Security Update : dhcp (openSUSE-2016-279)");
  script_summary(english:"Check for the openSUSE-2016-279 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dhcp fixes the following issues :

  - CVE-2015-8605: A remote attacker could have used badly
    formed packets with an invalid IPv4 UDP length field to
    cause a DHCP server, client, or relay program to
    terminate abnormally (boo#961305)

The following bugs were fixed :

  - boo#936923: Improper lease duration checking

  - boo#880984: Integer overflows in the date and time
    handling code

  - boo#956159: fixed service files to start dhcpd after
    slapd

  - boo#960506: Improve exit reason and logging when
    /sbin/dhclient-script is unable to pre-init requested
    interface

  - boo#947780: DHCP server could abort with 'Unable to set
    up timer: out of range' on very long or infinite timer
    intervals / lease lifetimes 

  - boo#912098: dhclient could pretend to run while silently
    declining leases

  - boo#919959: server: Do not log success report before
    send reported success

  - boo#928390: dhclient dit not expose next-server DHCPv4
    option to script

  - boo#926159: DHCP preferrend and valid lifetime would be
    logged incorrectly

  - boo#910686: Prevent a dependency conflict of dhcp-devel
    with bind-devel package"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=880984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961305"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"dhcp-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-client-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-client-debuginfo-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-debuginfo-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-debugsource-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-devel-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-relay-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-relay-debuginfo-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-server-4.2.6-9.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dhcp-server-debuginfo-4.2.6-9.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp / dhcp-client / dhcp-client-debuginfo / dhcp-debuginfo / etc");
}
