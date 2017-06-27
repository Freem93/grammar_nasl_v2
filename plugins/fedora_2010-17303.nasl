#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17303.
#

include("compat.inc");

if (description)
{
  script_id(50682);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:24:18 $");

  script_cve_id("CVE-2010-3611");
  script_bugtraq_id(44615);
  script_osvdb_id(68999);
  script_xref(name:"FEDORA", value:"2010-17303");

  script_name(english:"Fedora 13 : dhcp-4.1.1-27.P1.fc13 (2010-17303)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Nov 4 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.1.1-27.P1

    - Fix for CVE-2010-3611 (#649880)

    - Wed Oct 13 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-26.P1

    - Server was ignoring client's Solicit (where client
      included address/prefix as a preference) (#634842)

  - Tue Sep 7 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.1.1-25.P1

    - Hardening dhcpd/dhcrelay/dhclient by making them PIE &
      RELRO

    - Fri Aug 20 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-24.P1

    - Add DHCRELAYARGS variable to /etc/sysconfig/dhcrelay

    - Tue Jun 29 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-23.P1

    - Fix parsing of date (#514828)

    - Thu Jun 3 2010 Jiri Popelka <jpopelka at redhat.com> -
      12:4.1.1-22.P1

    - 4.1.1-P1 (pair of bug fixes including one for a
      security related bug).

    - Fix for CVE-2010-2156 (#601405)

    - Compile with -fno-strict-aliasing

    - N-V-R (copied from bind.spec):
      Name-Version-Release.Patch.dist

    - Mon May 3 2010 Jiri Popelka <jpopelka at redhat.com> -
      12:4.1.1-21

    - Fix the initialization-delay.patch (#587070)

    - Thu Apr 29 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-20

    - Cut down the 0-4 second delay before sending first
      DHCPDISCOVER (#587070)

    - Wed Apr 28 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-19

    - Move /etc/NetworkManager/dispatcher.d/10-dhclient
      script from dhcp to dhclient subpackage (#586999).

  - Wed Apr 28 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.1.1-18

    - Add domain-search to the list of default requested
      DHCP options (#586906)

    - Wed Apr 21 2010 Jiri Popelka <jpopelka at redhat.com>
      - 12:4.1.1-17

    - If the Reply was received in response to Renew or
      Rebind message, client adds any new addresses in the
      IA option to the IA (#578097)

  - Mon Apr 19 2010 Jiri Popelka <jpopelka at redhat.com> -
    12:4.1.1-16

    - Fill in Elapsed Time Option in Release/Decline
      messages (#582939)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=649877"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05939a43"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"dhcp-4.1.1-27.P1.fc13")) flag++;


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
