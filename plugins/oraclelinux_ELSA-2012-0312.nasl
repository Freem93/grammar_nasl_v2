#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0312 and 
# Oracle Linux Security Advisory ELSA-2012-0312 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68483);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2008-1198");
  script_osvdb_id(43144);
  script_xref(name:"RHSA", value:"2012:0312");

  script_name(english:"Oracle Linux 5 : initscripts (ELSA-2012-0312)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0312 :

An updated initscripts package that fixes one security issue and four
bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The initscripts package contains system scripts to boot your system,
change runlevels, activate and deactivate most network interfaces, and
shut the system down cleanly.

With the default IPsec (Internet Protocol Security) ifup script
configuration, the racoon IKE key management daemon used aggressive
IKE mode instead of main IKE mode. This resulted in the preshared key
(PSK) hash being sent unencrypted, which could make it easier for an
attacker able to sniff network traffic to obtain the plain text PSK
from a transmitted hash. (CVE-2008-1198)

Red Hat would like to thank Aleksander Adamowski for reporting this
issue.

This update also fixes the following bugs :

* Prior to this update, the DHCPv6 client was not terminated when the
network service was stopped. This update modifies the source so that
the client is now terminated when stopping the network service.
(BZ#568896)

* Prior to this update, on some systems the rm command failed and
reported the error message 'rm: cannot remove directory
`/var/run/dovecot/login/': Is a directory' during system boot. This
update modifies the source so that this error message no longer
appears. (BZ#679998)

* Prior to this update, the netconsole script could not discover and
resolve the MAC address of the router specified in the
/etc/sysconfig/netconsole file. This update modifies the netconsole
script so that the script no longer fails when the arping tool returns
the MAC address of the router more than once. (BZ#744734)

* Prior to this update, the arp_ip_target was, due to a logic error,
not correctly removed via sysfs. As a consequence, the error
'ifdown-eth: line 64: echo: write error: Invalid argument' was
reported when attempting to shut down a bonding device. This update
modifies the script so that the error no longer appears and
arp_ip_target is now correctly removed. (BZ#745681)

All users of initscripts are advised to upgrade to this updated
package, which fixes these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002663.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected initscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"initscripts-8.45.42-1.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "initscripts");
}
