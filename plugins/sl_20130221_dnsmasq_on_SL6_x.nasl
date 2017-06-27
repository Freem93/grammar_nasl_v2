#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64950);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/07 11:50:57 $");

  script_cve_id("CVE-2012-3411");

  script_name(english:"Scientific Linux Security Update : dnsmasq on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that dnsmasq, when used in combination with certain
libvirtd configurations, could incorrectly process network packets
from network interfaces that were intended to be prohibited. A remote,
unauthenticated attacker could exploit this flaw to cause a denial of
service via DNS amplification attacks. (CVE-2012-3411)

In order to fully address this issue, libvirt package users are
advised to install updated libvirt packages.

This update also fixes the following bug :

  - Due to a regression, the lease change script was
    disabled. Consequently, the 'dhcp-script' option in the
    /etc/dnsmasq.conf configuration file did not work. This
    update corrects the problem and the 'dhcp-script' option
    now works as expected.

This update also adds the following enhancements :

  - Prior to this update, dnsmasq did not validate that the
    tftp directory given actually existed and was a
    directory. Consequently, configuration errors were not
    immediately reported on startup. This update improves
    the code to validate the tftp root directory option. As
    a result, fault finding is simplified especially when
    dnsmasq is called by external processes such as libvirt.

  - The dnsmasq init script used an incorrect Process
    Identifier (PID) in the 'stop', 'restart', and
    'condrestart' commands. Consequently, if there were some
    dnsmasq instances running besides the system one started
    by the init script, then repeated calling of 'service
    dnsmasq' with 'stop' or 'restart' would kill all running
    dnsmasq instances, including ones not started with the
    init script. The dnsmasq init script code has been
    corrected to obtain the correct PID when calling the
    'stop', 'restart', and 'condrestart' commands. As a
    result, if there are dnsmasq instances running in
    addition to the system one started by the init script,
    then by calling 'service dnsmasq' with 'stop' or
    'restart' only the system one is stopped or restarted.

  - When two or more dnsmasq processes were running with
    DHCP enabled on one interface, DHCP RELEASE packets were
    sometimes lost. Consequently, when two or more dnsmasq
    processes were running with DHCP enabled on one
    interface, releasing IP addresses sometimes failed. This
    update sets the SO_BINDTODEVICE socket option on DHCP
    sockets if running dnsmasq with DHCP enabled on one
    interface. As a result, when two or more dnsmasq
    processes are running with DHCP enabled on one
    interface, they can release IP addresses as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=4544
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bcbdc64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected dnsmasq, dnsmasq-debuginfo and / or dnsmasq-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"dnsmasq-2.48-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dnsmasq-debuginfo-2.48-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dnsmasq-utils-2.48-13.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
