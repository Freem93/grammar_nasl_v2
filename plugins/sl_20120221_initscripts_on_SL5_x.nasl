#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61263);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2008-1198");

  script_name(english:"Scientific Linux Security Update : initscripts on SL5.x i386/x86_64");
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
"The initscripts package contains system scripts to boot your system,
change runlevels, activate and deactivate most network interfaces, and
shut the system down cleanly.

With the default IPsec (Internet Protocol Security) ifup script
configuration, the racoon IKE key management daemon used aggressive
IKE mode instead of main IKE mode. This resulted in the preshared key
(PSK) hash being sent unencrypted, which could make it easier for an
attacker able to sniff network traffic to obtain the plain text PSK
from a transmitted hash. (CVE-2008-1198)

This update also fixes the following bugs :

  - Prior to this update, the DHCPv6 client was not
    terminated when the network service was stopped. This
    update modifies the source so that the client is now
    terminated when stopping the network service.

  - Prior to this update, on some systems the rm command
    failed and reported the error message 'rm: cannot remove
    directory `/var/run/dovecot/login/': Is a directory'
    during system boot. This update modifies the source so
    that this error message no longer appears.

  - Prior to this update, the netconsole script could not
    discover and resolve the MAC address of the router
    specified in the /etc/sysconfig/netconsole file. This
    update modifies the netconsole script so that the script
    no longer fails when the arping tool returns the MAC
    address of the router more than once.

  - Prior to this update, the arp_ip_target was, due to a
    logic error, not correctly removed via sysfs. As a
    consequence, the error 'ifdown-eth: line 64: echo: write
    error: Invalid argument' was reported when attempting to
    shut down a bonding device. This update modifies the
    script so that the error no longer appears and
    arp_ip_target is now correctly removed.

All users of initscripts are advised to upgrade to this updated
package, which fixes these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3906
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?deb9c4b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected initscripts and / or initscripts-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"initscripts-8.45.42-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-debuginfo-8.45.42-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
