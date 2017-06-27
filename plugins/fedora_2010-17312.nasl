#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17312.
#

include("compat.inc");

if (description)
{
  script_id(50592);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/11 13:24:18 $");

  script_cve_id("CVE-2010-3611");
  script_bugtraq_id(44615);
  script_xref(name:"FEDORA", value:"2010-17312");

  script_name(english:"Fedora 14 : dhcp-4.2.0-14.P1.fc14 (2010-17312)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Nov 5 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-14.P1

    - fix broken dependencies

    - Thu Nov 4 2010 Jiri Popelka <jpopelka at redhat.com> -
      12:4.2.0-13.P1

    - 4.2.0-P1: fix for CVE-2010-3611 (#649880)

    - dhclient-script: when updating 'search' statement in
      resolv.conf, add domain part of hostname if it's not
      already there (#637763)

  - Wed Oct 13 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-12

    - Server was ignoring client's Solicit (where client
      included address/prefix as a preference) (#634842)

  - Thu Oct 7 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-11

    - Use ping instead of arping in dhclient-script to
      handle not-on-local-net gateway in ARP-less device
      (#524298)

  - Thu Oct 7 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-10

    - Check whether there is any unexpired address in
      previous lease prior to confirming (INIT-REBOOT) the
      lease (#585418)

  - Mon Oct 4 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-9

    - RFC 3442 - ignore Router option only if Classless
      Static Routes option contains default router

  - Thu Sep 30 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-8

    - Explicitly clear the ARP cache and flush all addresses
      & routes instead of bringing the interface down
      (#574568)

  - Tue Sep 7 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.2.0-7

    - Hardening dhcpd/dhcrelay/dhclient by making them PIE &
      RELRO

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=649877"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/050766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78f56165"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"dhcp-4.2.0-14.P1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
