#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0656-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97695);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7931", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_osvdb_id(151089, 151090, 151091, 151092, 151093, 151095, 151097, 151099, 151100, 151103, 151104, 151105, 151106, 151107, 151108, 151110, 151111, 151112, 151113, 151115, 151117, 151120, 151123, 151124, 151126, 151129, 151130, 151131);

  script_name(english:"SUSE SLES11 Security Update : tcpdump (SUSE-SU-2017:0656-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tcpdump fixes the following issues: Security issues
fixed (bsc#1020940) :

  - CVE-2016-7922: Corrected buffer overflow in AH parser
    print-ah.c:ah_print().

  - CVE-2016-7923: Corrected buffer overflow in ARP parser
    print-arp.c:arp_print().

  - CVE-2016-7925: Corrected buffer overflow in compressed
    SLIP parser print-sl.c:sl_if_print().

  - CVE-2016-7926: Corrected buffer overflow in the Ethernet
    parser print-ether.c:ethertype_print().

  - CVE-2016-7927: Corrected buffer overflow in the IEEE
    802.11 parser print-802_11.c:ieee802_11_radio_print().

  - CVE-2016-7928: Corrected buffer overflow in the IPComp
    parser print-ipcomp.c:ipcomp_print().

  - CVE-2016-7931: Corrected buffer overflow in the MPLS
    parser print-mpls.c:mpls_print().

  - CVE-2016-7936: Corrected buffer overflow in the UDP
    parser print-udp.c:udp_print().

  - CVE-2016-7934,CVE-2016-7935,CVE-2016-7937: Corrected
    segmentation faults in function udp_print().

  - CVE-2016-7939: Corrected buffer overflows in GRE parser
    print-gre.c:(multiple functions).

  - CVE-2016-7940: Corrected buffer overflows in STP parser
    print-stp.c:(multiple functions).

  - CVE-2016-7973: Corrected buffer overflow in AppleTalk
    parser print-atalk.c.

  - CVE-2016-7974: Corrected buffer overflow in IP parser
    print-ip.c:(multiple functions).

  - CVE-2016-7975: Corrected buffer overflow in TCP parser
    print-tcp.c:tcp_print().

  - CVE-2016-7983,CVE-2016-7984: Corrected buffer overflow
    in TFTP parser print-tftp.c:tftp_print().

  - CVE-2016-7992: Corrected buffer overflow in Classical IP
    over ATM parser print-cip.c.

  - CVE-2016-7993: Corrected buffer overflow in multiple
    protocol parsers (DNS, DVMRP, HSRP, etc.).

  - CVE-2016-8574: Corrected buffer overflow in FRF.15
    parser print-fr.c:frf15_print().

  - CVE-2017-5202: Corrected buffer overflow in ISO CLNS
    parser print-isoclns.c:clnp_print().

  - CVE-2017-5203: Corrected buffer overflow in BOOTP parser
    print-bootp.c:bootp_print().

  - CVE-2017-5204: Corrected buffer overflow in IPv6 parser
    print-ip6.c:ip6_print().

  - CVE-2017-5483: Corrected buffer overflow in SNMP parser
    print-snmp.c:asn1_parse().

  - CVE-2017-5484: Corrected buffer overflow in ATM parser
    print-atm.c:sig_print().

  - CVE-2017-5485: Corrected buffer overflow in ISO CLNS
    parser addrtoname.c:lookup_nsap().

  - CVE-2017-5486: Corrected buffer overflow in ISO CLNS
    parser print-isoclns.c:clnp_print().

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7923.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7927.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7931.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7934.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7936.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7940.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7973.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7992.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7993.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5486.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170656-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cf79329"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-tcpdump-13021=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-tcpdump-13021=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"tcpdump-3.9.8-1.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
