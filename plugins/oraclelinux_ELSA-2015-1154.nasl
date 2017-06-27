#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1154 and 
# Oracle Linux Security Advisory ELSA-2015-1154 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84354);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2015-3204");
  script_bugtraq_id(75392);
  script_osvdb_id(122807, 122814);
  script_xref(name:"RHSA", value:"2015:1154");

  script_name(english:"Oracle Linux 7 : libreswan (ELSA-2015-1154)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1154 :

Updated libreswan packages that fix one security issue, several bugs
and add two enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Libreswan is an implementation of IPsec & IKE for Linux. IPsec is the
Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services. These services allow you
to build secure tunnels through untrusted networks such as virtual
private network (VPN).

A flaw was discovered in the way Libreswan's IKE daemon processed
certain IKEv1 payloads. A remote attacker could send specially crafted
IKEv1 payloads that, when processed, would lead to a denial of service
(daemon crash). (CVE-2015-3204)

Red Hat would like to thank Javantea for reporting this issue.

This update fixes the following bugs :

* Previously, the programs/pluto/state.h and
programs/pluto/kernel_netlink.c files had a maximum SELinux context
size of 257 and 1024 respectively. These restrictions set by libreswan
limited the size of the context that can be exchanged by pluto (the
IPSec daemon) when using a Labeled Internet Protocol Security (IPsec).
The SElinux labels for Labeled IPsec have been extended to 4096 bytes
and the mentioned restrictions no longer exist. (BZ#1198650)

* On some architectures, the kernel AES_GCM IPsec algorithm did not
work properly with acceleration drivers. On those kernels, some
acceleration modules are added to the modprobe blacklist. However,
Libreswan was ignoring this blacklist, leading to AES_GCM failures.
This update adds support for the module blacklist to the libreswan
packages and thus prevents the AES_GCM failures from occurring.
(BZ#1208022)

* An IPv6 issue has been resolved that prevented ipv6-icmp Neighbour
Discovery from working properly once an IPsec tunnel is established
(and one endpoint reboots). When upgrading, ensure that
/etc/ipsec.conf is loading all /etc/ipsec.d/*conf files using the
/etc/ipsec.conf 'include' statement, or explicitly include this new
configuration file in /etc/ipsec.conf. (BZ#1208023)

* A FIPS self-test prevented libreswan from properly starting in FIPS
mode. This bug has been fixed and libreswan now works in FIPS mode as
expected. (BZ#1211146)

In addition, this update adds the following enhancements :

* A new option 'seedbits=' has been added to pre-seed the Network
Security Services (NSS) pseudo random number generator (PRNG) function
with entropy from the /dev/random file on startup. This option is
disabled by default. It can be enabled by setting the 'seedbits='
option in the 'config setup' section in the /etc/ipsec.conf file.
(BZ#1198649)

* The build process now runs a Cryptographic Algorithm Validation
Program (CAVP) certification test on the Internet Key Exchange version
1 and 2 (IKEv1 and IKEv2) PRF/PRF+ functions. (BZ#1213652)

All libreswan users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-June/005142.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreswan package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreswan-3.12-10.1.0.1.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreswan");
}
