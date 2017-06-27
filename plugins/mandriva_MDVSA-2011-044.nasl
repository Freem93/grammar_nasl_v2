#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:044. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(52593);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_cve_id("CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1142", "CVE-2011-1143");
  script_bugtraq_id(46167, 46416, 46626);
  script_xref(name:"MDVSA", value:"2011:044");

  script_name(english:"Mandriva Linux Security Advisory : wireshark (MDVSA-2011:044)");
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
"This advisory updates wireshark to the latest version (1.2.15), fixing
several security issues :

Wireshark 1.5.0, 1.4.3, and earlier frees an uninitialized pointer
during processing of a .pcap file in the pcap-ng format, which allows
remote attackers to cause a denial of service (memory corruption) or
possibly have unspecified other impact via a malformed file
(CVE-2011-0538).

Heap-based buffer overflow in wiretap/dct3trace.c in Wireshark 1.2.0
through 1.2.14 and 1.4.0 through 1.4.3 allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via a long record in a Nokia DCT3 trace file
(CVE-2011-0713).

wiretap/pcapng.c in Wireshark 1.2.0 through 1.2.14 and 1.4.0 through
1.4.3 allows remote attackers to cause a denial of service
(application crash) via a pcap-ng file that contains a large
packet-length field (CVE-2011-1139).

Multiple stack consumption vulnerabilities in the
dissect_ms_compressed_string and dissect_mscldap_string functions in
Wireshark 1.0.x, 1.2.0 through 1.2.14, and 1.4.0 through 1.4.3 allow
remote attackers to cause a denial of service (infinite recursion) via
a crafted (1) SMB or (2) Connection-less LDAP (CLDAP) packet
(CVE-2011-1140).

epan/dissectors/packet-ldap.c in Wireshark 1.0.x, 1.2.0 through
1.2.14, and 1.4.0 through 1.4.3 allows remote attackers to cause a
denial of service (memory consumption) via (1) a long LDAP filter
string or (2) an LDAP filter string containing many elements
(CVE-2011-1141).

Stack consumption vulnerability in the dissect_ber_choice function in
the BER dissector in Wireshark 1.2.x through 1.2.15 and 1.4.x through
1.4.4 might allow remote attackers to cause a denial of service
(infinite loop) via vectors involving self-referential ASN.1 CHOICE
values (CVE-2011-1142).

epan/dissectors/packet-ntlmssp.c in the NTLMSSP dissector in Wireshark
before 1.4.4 allows remote attackers to cause a denial of service
(NULL pointer dereference and application crash) via a crafted .pcap
file (CVE-2011-1143).

The updated packages have been upgraded to the latest 1.2.x version
(1.2.15) and patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.15.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dumpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwireshark0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rawshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"dumpcap-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64wireshark-devel-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64wireshark0-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libwireshark-devel-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libwireshark0-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"rawshark-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tshark-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"wireshark-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"wireshark-tools-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"dumpcap-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wireshark-devel-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wireshark0-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwireshark-devel-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwireshark0-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rawshark-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tshark-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"wireshark-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"wireshark-tools-1.2.15-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
