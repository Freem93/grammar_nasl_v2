#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:055. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66069);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2012-2392",
    "CVE-2012-2393",
    "CVE-2012-2394",
    "CVE-2012-3548",
    "CVE-2012-4048",
    "CVE-2012-4049",
    "CVE-2012-4285",
    "CVE-2012-4288",
    "CVE-2012-4289",
    "CVE-2012-4290",
    "CVE-2012-4291",
    "CVE-2012-4292",
    "CVE-2012-4293",
    "CVE-2012-4296",
    "CVE-2012-4297",
    "CVE-2012-6054",
    "CVE-2012-6056",
    "CVE-2013-2478",
    "CVE-2013-2480",
    "CVE-2013-2481",
    "CVE-2013-2482",
    "CVE-2013-2483",
    "CVE-2013-2484",
    "CVE-2013-2485",
    "CVE-2013-2488"
  );
  script_bugtraq_id(
    53651,
    53652,
    53653,
    54649,
    55035,
    56729,
    58340,
    58351,
    58353,
    58355,
    58356,
    58357,
    58362,
    58365
  );
  script_osvdb_id(
    82098,
    82099,
    82100,
    82155,
    82156,
    82157,
    82158,
    82159,
    82160,
    84260,
    84261,
    84776,
    84777,
    84778,
    84779,
    84780,
    84781,
    84786,
    84787,
    84788,
    85092,
    87995,
    87996,
    90991,
    90993,
    90995,
    90996,
    90997,
    90998,
    90999,
    91000,
    91001
  );
  script_xref(name:"MDVSA", value:"2013:055");
  script_xref(name:"MGASA", value:"2012-0134");
  script_xref(name:"MGASA", value:"2012-0210");
  script_xref(name:"MGASA", value:"2012-0226");
  script_xref(name:"MGASA", value:"2012-0284");
  script_xref(name:"MGASA", value:"2012-0348");
  script_xref(name:"MGASA", value:"2013-0034");
  script_xref(name:"MGASA", value:"2013-0090");

  script_name(english:"Mandriva Linux Security Advisory : wireshark (MDVSA-2013:055)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in wireshark :

Infinite and large loops in ANSI MAP, BACapp, Bluetooth HCI, IEEE
802.3, LTP, and R3 dissectors have been fixed. Discovered by Laurent
Butti (http://www.wireshark.org/security/wnpa-sec-2012-08.html
[CVE-2012-2392])

The DIAMETER dissector could try to allocate memory improperly and
crash (http://www.wireshark.org/security/wnpa-sec-2012-09.html
[CVE-2012-2393])

Wireshark could crash on SPARC processors due to misaligned memory.
Discovered by Klaus Heckelmann
(http://www.wireshark.org/security/wnpa-sec-2012-10.html
[CVE-2012-2394])

The PPP dissector in Wireshark 1.4.x before 1.4.14, 1.6.x before
1.6.9, and 1.8.x before 1.8.1 allows remote attackers to cause a
denial of service (invalid pointer dereference and application crash)
via a crafted packet, as demonstrated by a usbmon dump
(CVE-2012-4048).

epan/dissectors/packet-nfs.c in the NFS dissector in Wireshark 1.4.x
before 1.4.14, 1.6.x before 1.6.9, and 1.8.x before 1.8.1 allows
remote attackers to cause a denial of service (loop and CPU
consumption) via a crafted packet (CVE-2012-4049).

The DCP ETSI dissector could trigger a zero division (CVE-2012-4285).

The XTP dissector could go into an infinite loop (CVE-2012-4288).

The AFP dissector could go into a large loop (CVE-2012-4289).

The RTPS2 dissector could overflow a buffer (CVE-2012-4296).

The GSM RLC MAC dissector could overflow a buffer (CVE-2012-4297).

The CIP dissector could exhaust system memory (CVE-2012-4291).

The STUN dissector could crash (CVE-2012-4292).

The EtherCAT Mailbox dissector could abort (CVE-2012-4293).

The CTDB dissector could go into a large loop (CVE-2012-4290).

Martin Wilck discovered an infinite loop in the DRDA dissector
(CVE-2012-5239).

The USB dissector could go into an infinite loop. (wnpa-sec-2012-31)

The ISAKMP dissector could crash. (wnpa-sec-2012-35)

The iSCSI dissector could go into an infinite loop. (wnpa-sec-2012-36)

The WTP dissector could go into an infinite loop. (wnpa-sec-2012-37)

The RTCP dissector could go into an infinite loop. (wnpa-sec-2012-38)

The ICMPv6 dissector could go into an infinite loop.
(wnpa-sec-2012-40)

Infinite and large loops in the Bluetooth HCI, CSN.1, DCP-ETSI DOCSIS
CM-STAUS, IEEE 802.3 Slow Protocols, MPLS, R3, RTPS, SDP, and SIP
dissectors (wnpa-sec-2013-01).

The CLNP dissector could crash (wnpa-sec-2013-02).

The DTN dissector could crash (wnpa-sec-2013-03).

The MS-MMC dissector (and possibly others) could crash
(wnpa-sec-2013-04).

The DTLS dissector could crash (wnpa-sec-2013-05).

The DCP-ETSI dissector could corrupt memory (wnpa-sec-2013-07).

The Wireshark dissection engine could crash (wnpa-sec-2013-08).

The NTLMSSP dissector could overflow a buffer (wnpa-sec-2013-09).

The sFlow dissector could go into an infinite loop (CVE-2012-6054).

The SCTP dissector could go into an infinite loop (CVE-2012-6056).

The MS-MMS dissector could crash (CVE-2013-2478).

The RTPS and RTPS2 dissectors could crash (CVE-2013-2480).

The Mount dissector could crash (CVE-2013-2481).

The AMPQ dissector could go into an infinite loop (CVE-2013-2482).

The ACN dissector could attempt to divide by zero (CVE-2013-2483).

The CIMD dissector could crash (CVE-2013-2484).

The FCSP dissector could go into an infinite loop (CVE-2013-2485).

The DTLS dissector could crash (CVE-2013-2488).

This advisory provides the latest version of Wireshark (1.6.14) which
is not vulnerable to these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dumpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rawshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dumpcap-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark-devel-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark1-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rawshark-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tshark-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-1.6.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-tools-1.6.14-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
