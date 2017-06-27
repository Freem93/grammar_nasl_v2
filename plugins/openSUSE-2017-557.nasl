#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-557.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100040);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2014-8767", "CVE-2014-8768", "CVE-2014-8769", "CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155", "CVE-2015-3138", "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");

  script_name(english:"openSUSE Security Update : tcpdump / libpcap (openSUSE-2017-557)");
  script_summary(english:"Check for the openSUSE-2017-557 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tcpdump to version 4.9.0 and libpcap to version 1.8.1
fixes the several issues.

These security issues were fixed in tcpdump :

  - CVE-2016-7922: The AH parser in tcpdump had a buffer
    overflow in print-ah.c:ah_print() (bsc#1020940).

  - CVE-2016-7923: The ARP parser in tcpdump had a buffer
    overflow in print-arp.c:arp_print() (bsc#1020940).

  - CVE-2016-7924: The ATM parser in tcpdump had a buffer
    overflow in print-atm.c:oam_print() (bsc#1020940).

  - CVE-2016-7925: The compressed SLIP parser in tcpdump had
    a buffer overflow in print-sl.c:sl_if_print()
    (bsc#1020940).

  - CVE-2016-7926: The Ethernet parser in tcpdump had a
    buffer overflow in print-ether.c:ethertype_print()
    (bsc#1020940).

  - CVE-2016-7927: The IEEE 802.11 parser in tcpdump had a
    buffer overflow in
    print-802_11.c:ieee802_11_radio_print() (bsc#1020940).

  - CVE-2016-7928: The IPComp parser in tcpdump had a buffer
    overflow in print-ipcomp.c:ipcomp_print() (bsc#1020940).

  - CVE-2016-7929: The Juniper PPPoE ATM parser in tcpdump
    had a buffer overflow in
    print-juniper.c:juniper_parse_header() (bsc#1020940).

  - CVE-2016-7930: The LLC/SNAP parser in tcpdump had a
    buffer overflow in print-llc.c:llc_print()
    (bsc#1020940).

  - CVE-2016-7931: The MPLS parser in tcpdump had a buffer
    overflow in print-mpls.c:mpls_print() (bsc#1020940).

  - CVE-2016-7932: The PIM parser in tcpdump had a buffer
    overflow in print-pim.c:pimv2_check_checksum()
    (bsc#1020940).

  - CVE-2016-7933: The PPP parser in tcpdump had a buffer
    overflow in print-ppp.c:ppp_hdlc_if_print()
    (bsc#1020940).

  - CVE-2016-7934: The RTCP parser in tcpdump had a buffer
    overflow in print-udp.c:rtcp_print() (bsc#1020940).

  - CVE-2016-7935: The RTP parser in tcpdump had a buffer
    overflow in print-udp.c:rtp_print() (bsc#1020940).

  - CVE-2016-7936: The UDP parser in tcpdump had a buffer
    overflow in print-udp.c:udp_print() (bsc#1020940).

  - CVE-2016-7937: The VAT parser in tcpdump had a buffer
    overflow in print-udp.c:vat_print() (bsc#1020940).

  - CVE-2016-7938: The ZeroMQ parser in tcpdump had an
    integer overflow in print-zeromq.c:zmtp1_print_frame()
    (bsc#1020940).

  - CVE-2016-7939: The GRE parser in tcpdump had a buffer
    overflow in print-gre.c, multiple functions
    (bsc#1020940).

  - CVE-2016-7940: The STP parser in tcpdump had a buffer
    overflow in print-stp.c, multiple functions
    (bsc#1020940).

  - CVE-2016-7973: The AppleTalk parser in tcpdump had a
    buffer overflow in print-atalk.c, multiple functions
    (bsc#1020940).

  - CVE-2016-7974: The IP parser in tcpdump had a buffer
    overflow in print-ip.c, multiple functions
    (bsc#1020940).

  - CVE-2016-7975: The TCP parser in tcpdump had a buffer
    overflow in print-tcp.c:tcp_print() (bsc#1020940).

  - CVE-2016-7983: The BOOTP parser in tcpdump had a buffer
    overflow in print-bootp.c:bootp_print() (bsc#1020940).

  - CVE-2016-7984: The TFTP parser in tcpdump had a buffer
    overflow in print-tftp.c:tftp_print() (bsc#1020940).

  - CVE-2016-7985: The CALM FAST parser in tcpdump had a
    buffer overflow in print-calm-fast.c:calm_fast_print()
    (bsc#1020940).

  - CVE-2016-7986: The GeoNetworking parser in tcpdump had a
    buffer overflow in print-geonet.c, multiple functions
    (bsc#1020940).

  - CVE-2016-7992: The Classical IP over ATM parser in
    tcpdump had a buffer overflow in
    print-cip.c:cip_if_print() (bsc#1020940).

  - CVE-2016-7993: A bug in util-print.c:relts_print() in
    tcpdump could cause a buffer overflow in multiple
    protocol parsers (DNS, DVMRP, HSRP, IGMP, lightweight
    resolver protocol, PIM) (bsc#1020940).

  - CVE-2016-8574: The FRF.15 parser in tcpdump had a buffer
    overflow in print-fr.c:frf15_print() (bsc#1020940).

  - CVE-2016-8575: The Q.933 parser in tcpdump had a buffer
    overflow in print-fr.c:q933_print(), a different
    vulnerability than CVE-2017-5482 (bsc#1020940).

  - CVE-2017-5202: The ISO CLNS parser in tcpdump had a
    buffer overflow in print-isoclns.c:clnp_print()
    (bsc#1020940).

  - CVE-2017-5203: The BOOTP parser in tcpdump had a buffer
    overflow in print-bootp.c:bootp_print() (bsc#1020940).

  - CVE-2017-5204: The IPv6 parser in tcpdump had a buffer
    overflow in print-ip6.c:ip6_print() (bsc#1020940).

  - CVE-2017-5205: The ISAKMP parser in tcpdump had a buffer
    overflow in print-isakmp.c:ikev2_e_print()
    (bsc#1020940).

  - CVE-2017-5341: The OTV parser in tcpdump had a buffer
    overflow in print-otv.c:otv_print() (bsc#1020940).

  - CVE-2017-5342: In tcpdump a bug in multiple protocol
    parsers (Geneve, GRE, NSH, OTV, VXLAN and VXLAN GPE)
    could cause a buffer overflow in
    print-ether.c:ether_print() (bsc#1020940).

  - CVE-2017-5482: The Q.933 parser in tcpdump had a buffer
    overflow in print-fr.c:q933_print(), a different
    vulnerability than CVE-2016-8575 (bsc#1020940).

  - CVE-2017-5483: The SNMP parser in tcpdump had a buffer
    overflow in print-snmp.c:asn1_parse() (bsc#1020940).

  - CVE-2017-5484: The ATM parser in tcpdump had a buffer
    overflow in print-atm.c:sig_print() (bsc#1020940).

  - CVE-2017-5485: The ISO CLNS parser in tcpdump had a
    buffer overflow in addrtoname.c:lookup_nsap()
    (bsc#1020940).

  - CVE-2017-5486: The ISO CLNS parser in tcpdump had a
    buffer overflow in print-isoclns.c:clnp_print()
    (bsc#1020940).

  - CVE-2015-3138: Fixed potential denial of service in
    print-wb.c (bsc#927637).

  - CVE-2015-0261: Integer signedness error in the
    mobility_opt_print function in the IPv6 mobility printer
    in tcpdump allowed remote attackers to cause a denial of
    service (out-of-bounds read and crash) or possibly
    execute arbitrary code via a negative length value
    (bsc#922220).

  - CVE-2015-2153: The rpki_rtr_pdu_print function in
    print-rpki-rtr.c in the TCP printer in tcpdump allowed
    remote attackers to cause a denial of service
    (out-of-bounds read or write and crash) via a crafted
    header length in an RPKI-RTR Protocol Data Unit (PDU)
    (bsc#922221).

  - CVE-2015-2154: The osi_print_cksum function in
    print-isoclns.c in the ethernet printer in tcpdump
    allowed remote attackers to cause a denial of service
    (out-of-bounds read and crash) via a crafted (1) length,
    (2) offset, or (3) base pointer checksum value
    (bsc#922222).

  - CVE-2015-2155: The force printer in tcpdump allowed
    remote attackers to cause a denial of service (crash)
    and possibly execute arbitrary code via unspecified
    vectors (bsc#922223).

  - CVE-2014-8767: Integer underflow in the olsr_print
    function in tcpdump 3.9.6 when in verbose mode, allowed
    remote attackers to cause a denial of service (crash)
    via a crafted length value in an OLSR frame
    (bsc#905870).

  - CVE-2014-8768: Multiple Integer underflows in the
    geonet_print function in tcpdump when run in verbose
    mode, allowed remote attackers to cause a denial of
    service (segmentation fault and crash) via a crafted
    length value in a Geonet frame (bsc#905871).

  - CVE-2014-8769: tcpdump might have allowed remote
    attackers to obtain sensitive information from memory or
    cause a denial of service (packet loss or segmentation
    fault) via a crafted Ad hoc On-Demand Distance Vector
    (AODV) packet, which triggers an out-of-bounds memory
    access (bsc#905872).

These non-security issues were fixed in tcpdump :

  - PPKI to Router Protocol: Fix Segmentation Faults and
    other problems

  - RPKI to Router Protocol: print strings with fn_printn()

  - Added a short option '#', same as long option '--number'

  - nflog, mobile, forces, pptp, AODV, AHCP, IPv6, OSPFv4,
    RPL, DHCPv6 enhancements/fixes

  - M3UA decode added.

  - Added bittok2str().

  - A number of unaligned access faults fixed

  - The -A flag does not consider CR to be printable anymore

  - fx.lebail took over coverity baby sitting

  - Default snapshot size increased to 256K for accomodate
    USB captures

These non-security issues were fixed in libpcap :

  - Provide a -devel-static subpackage that contains the
    static libraries and all the extra dependencies which
    are not needed for dynamic linking.

  - Fix handling of packet count in the TPACKET_V3 inner
    loop

  - Filter out duplicate looped back CAN frames.

  - Fix the handling of loopback filters for IPv6 packets.

  - Add a link-layer header type for RDS (IEC 62106) groups.

  - Handle all CAN captures with pcap-linux.c, in cooked
    mode.

  - Removes the need for the 'host-endian' link-layer header
    type.

  - Have separate DLTs for big-endian and host-endian
    SocketCAN headers.

  - Properly check for sock_recv() errors.

  - Re-impose some of Winsock's limitations on sock_recv().

  - Replace sprintf() with pcap_snprintf().

  - Fix signature of pcap_stats_ex_remote().

  - Have rpcap_remoteact_getsock() return a SOCKET and
    supply an 'is active' flag.

  - Clean up {DAG, Septel, Myricom SNF}-only builds.

  - pcap_create_interface() needs the interface name on
    Linux.

  - Clean up hardware time stamp support: the 'any' device
    does not support any time stamp types.

  - Recognize 802.1ad nested VLAN tag in vlan filter.

  - Support for filtering Geneve encapsulated packets.

  - Fix handling of zones for BPF on Solaris

  - Added bpf_filter1() with extensions

  - EBUSY can now be returned by SNFv3 code.

  - Don't crash on filters testing a non-existent link-layer
    type field.

  - Fix sending in non-blocking mode on Linux with
    memory-mapped capture.

  - Fix timestamps when reading pcap-ng files on big-endian
    machines.

  - Fixes for byte order issues with NFLOG captures

  - Handle using cooked mode for DLT_NETLINK in
    activate_new().

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/322955"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump / libpcap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcap1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libpcap-debugsource-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcap-devel-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcap-devel-static-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcap1-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpcap1-debuginfo-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tcpdump-4.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tcpdump-debuginfo-4.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tcpdump-debugsource-4.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcap-devel-32bit-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcap1-32bit-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpcap1-debuginfo-32bit-1.8.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcap-debugsource-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcap-devel-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcap-devel-static-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcap1-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpcap1-debuginfo-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcap-devel-32bit-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcap1-32bit-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpcap1-debuginfo-32bit-1.8.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"tcpdump-4.9.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"tcpdump-debuginfo-4.9.0-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"tcpdump-debugsource-4.9.0-6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcap-debugsource / libpcap-devel / libpcap-devel-32bit / etc");
}
