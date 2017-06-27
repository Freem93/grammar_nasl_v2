#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-74.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74794);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2011-4182");

  script_name(english:"openSUSE Security Update : sysconfig (openSUSE-2012-74)");
  script_summary(english:"Check for the openSUSE-2012-74 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixed to quote config / interface variables in
    ifservices script and cleaned up content of the ESSID
    which gets appended to them by NetworkManager dispatcher
    hook (bnc#735394, CVE-2011-4182). Fixed also to return
    proper exit code 0 in NM dispatcher hooks.

  - Changed to call ip addr flush in ifdown, but after ip
    link set down as it does not cause ipv6 sysctl tree side
    effects then at least with more recent kernels
    (bnc#580018,bnc#559170).

  - Explicitly disabled posix mode in all bash scripts as we
    are using several features not supported in posix mode
    (bnc#739338).

  - Fixed ipv6 dad / link ready wait time calculation (1/10
    of the specified time) and replaced useless up flag
    check loop with link_ready_wait to avoid send errors
    from dhclient6 (bnc#697929).

  - Added to require vlan, bridge-utils and tunctl packages
    via spec, that are often required in base networking
    configurations and are missed otherwise in 2nd
    installation stage, that may be unable to install them
    for some reason (bnc#733118).

  - Added X-Systemd-RemainAfterExit: true LSB header
    (bnc#727771)

  - Do not suggest dhcp6c client from dropped dhcpv6 package
    in ifup-dhcp, marked dhcp6c as deprecated in
    network/dhcp and changed to use dhclient6 as first
    choice (bnc#734723)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=559170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=697929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739338"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysconfig packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysconfig-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysconfig-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/20");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"sysconfig-0.75.4-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"sysconfig-debuginfo-0.75.4-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"sysconfig-debugsource-0.75.4-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysconfig / sysconfig-debuginfo / sysconfig-debugsource");
}
