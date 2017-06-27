#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(84393);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/07/06 13:45:35 $");

  script_cve_id("CVE-2015-3204");

  script_name(english:"Scientific Linux Security Update : libreswan on SL7.x x86_64");
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
"A flaw was discovered in the way Libreswan's IKE daemon processed
certain IKEv1 payloads. A remote attacker could send specially crafted
IKEv1 payloads that, when processed, would lead to a denial of service
(daemon crash). (CVE-2015-3204)

This update fixes the following bugs :

  - Previously, the programs/pluto/state.h and
    programs/pluto/kernel_netlink.c files had a maximum
    SELinux context size of 257 and 1024 respectively. These
    restrictions set by libreswan limited the size of the
    context that can be exchanged by pluto (the IPSec
    daemon) when using a Labeled Internet Protocol Security
    (IPsec). The SElinux labels for Labeled IPsec have been
    extended to 4096 bytes and the mentioned restrictions no
    longer exist.

  - On some architectures, the kernel AES_GCM IPsec
    algorithm did not work properly with acceleration
    drivers. On those kernels, some acceleration modules are
    added to the modprobe blacklist. However, Libreswan was
    ignoring this blacklist, leading to AES_GCM failures.
    This update adds support for the module blacklist to the
    libreswan packages and thus prevents the AES_GCM
    failures from occurring.

  - An IPv6 issue has been resolved that prevented ipv6-icmp
    Neighbour Discovery from working properly once an IPsec
    tunnel is established (and one endpoint reboots). When
    upgrading, ensure that /etc/ipsec.conf is loading all
    /etc/ipsec.d/*conf files using the /etc/ipsec.conf
    'include' statement, or explicitly include this new
    configuration file in /etc/ipsec.conf.

  - A FIPS self-test prevented libreswan from properly
    starting in FIPS mode. This bug has been fixed and
    libreswan now works in FIPS mode as expected.

In addition, this update adds the following enhancements :

  - A new option 'seedbits=' has been added to pre-seed the
    Network Security Services (NSS) pseudo random number
    generator (PRNG) function with entropy from the
    /dev/random file on startup. This option is disabled by
    default. It can be enabled by setting the 'seedbits='
    option in the 'config setup' section in the
    /etc/ipsec.conf file.

  - The build process now runs a Cryptographic Algorithm
    Validation Program (CAVP) certification test on the
    Internet Key Exchange version 1 and 2 (IKEv1 and IKEv2)
    PRF/PRF+ functions."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=12300
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cd48c00"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreswan and / or libreswan-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreswan-3.12-10.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreswan-debuginfo-3.12-10.1.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
