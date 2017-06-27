#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:279. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(71074);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/15 02:06:32 $");

  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6339", "CVE-2013-6340");
  script_bugtraq_id(63500, 63501, 63502, 63503, 63504);
  script_xref(name:"MDVSA", value:"2013:279");

  script_name(english:"Mandriva Linux Security Advisory : wireshark (MDVSA-2013:279)");
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
"Multiple vulnerabilities was found and corrected in Wireshark :

The ieee802154_map_rec function in epan/dissectors/packet-ieee802154.c
in the IEEE 802.15.4 dissector in Wireshark 1.8.x before 1.8.11 and
1.10.x before 1.10.3 uses an incorrect pointer chain, which allows
remote attackers to cause a denial of service (application crash) via
a crafted packet (CVE-2013-6336).

Unspecified vulnerability in the NBAP dissector in Wireshark 1.8.x
before 1.8.11 and 1.10.x before 1.10.3 allows remote attackers to
cause a denial of service (application crash) via a crafted packet
(CVE-2013-6337).

The dissect_sip_common function in epan/dissectors/packet-sip.c in the
SIP dissector in Wireshark 1.8.x before 1.8.11 and 1.10.x before
1.10.3 does not properly initialize a data structure, which allows
remote attackers to cause a denial of service (application crash) via
a crafted packet (CVE-2013-6338).

The dissect_openwire_type function in
epan/dissectors/packet-openwire.c in the OpenWire dissector in
Wireshark 1.8.x before 1.8.11 and 1.10.x before 1.10.3 allows remote
attackers to cause a denial of service (loop) via a crafted packet
(CVE-2013-6339).

epan/dissectors/packet-tcp.c in the TCP dissector in Wireshark 1.8.x
before 1.8.11 and 1.10.x before 1.10.3 does not properly determine the
amount of remaining data, which allows remote attackers to cause a
denial of service (application crash) via a crafted packet
(CVE-2013-6340).

This advisory provides the latest version of Wireshark (1.8.11) which
is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2013-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2013-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2013-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2013-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2013-65.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dumpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rawshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dumpcap-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark-devel-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark2-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rawshark-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tshark-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-1.8.11-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-tools-1.8.11-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
