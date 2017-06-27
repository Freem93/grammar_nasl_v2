#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0058.
#

include("compat.inc");

if (description)
{
  script_id(91742);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2011-0997", "CVE-2011-2748", "CVE-2011-2749", "CVE-2012-3571");
  script_bugtraq_id(47176, 49120, 54665);
  script_osvdb_id(71493, 74556, 74557, 84255);

  script_name(english:"OracleVM 3.2 : dhcp (OVMSA-2016-0058)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - exit(2) after sending DHCPDECLINE when dhclient has been
    started with '-1' (RHBZ #756490)

  - An error in the handling of malformed client identifiers
    can cause a denial-of-service condition in affected
    servers. (CVE-2012-3571, #843125)

  - Propagate libdhcp timeout to internal timeout_arg (RHBZ
    #736515)

  - A pair of defects cause the server to halt upon
    processing certain packets (CVE-2011-2748,
    CVE-2011-2749, #729881)

  - dhclient.conf(5), dhclient(8) mention that interface-mtu
    option is also requested by default (RHBZ #694264)

  - Better fix for CVE-2011-0997: making domain-name check
    more lenient (RHBZ #690577)

  - dhclient requests interface-mtu option by default (RHBZ
    #694264)

  - dhclient.conf(5) fix (RHBZ #585855)

  - Make dhcpd init script LSB compliant (RHBZ #610128)

  - Use PID for seeding the random number generator in
    dhclient (RHBZ #623953)

  - Add DHCRELAYARGS variable to /etc/sysconfig/dhcrelay
    (RHBZ #624965)

  - 'lease imbalance' messages are not logged unless
    rebalance was actually attempted (RHBZ #661939)

  - Explicitly clear the ARP cache and flush all addresses &
    routes instead of bringing the interface down (RHBZ
    #685048)

  - IPoIB support (RHBZ #660679)

  - dhclient: insufficient sanitization of certain DHCP
    response values (CVE-2011-0997, #690577)

  - A partner-down failover server no longer emits 'peer
    holds all free leases' if it is able to newly-allocate
    one of the peer's leases. (RHBZ #610219)

  - The server's 'by client-id' and 'by hardware address'
    hash table lists are now sorted according to the
    preference to re-allocate that lease to returning
    clients. This should eliminate pool starvation problems
    arising when 'INIT' clients were given new leases rather
    than presently active ones. (RHBZ #615995)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000486.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dhclient package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:dhclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"dhclient-3.0.5-33.el5_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient");
}
