#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:188. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(77888);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/11/21 15:59:35 $");

  script_cve_id("CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");
  script_bugtraq_id(69853, 69855, 69856, 69857, 69858, 69859, 69860, 69861, 69862, 69865);
  script_xref(name:"MDVSA", value:"2014:188");

  script_name(english:"Mandriva Linux Security Advisory : wireshark (MDVSA-2014:188)");
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
"Updated wireshark packages fix security vulnerabilities :

RTP dissector crash (CVE-2014-6421, CVE-2014-6422).

MEGACO dissector infinite loop (CVE-2014-6423).

Netflow dissector crash (CVE-2014-6424).

RTSP dissector crash (CVE-2014-6427).

SES dissector crash (CVE-2014-6428).

Sniffer file parser crash (CVE-2014-6429, CVE-2014-6430,
CVE-2014-6431, CVE-2014-6432)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0386.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dumpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wiretap3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wsutil3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rawshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dumpcap-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark-devel-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wireshark3-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wiretap3-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64wsutil3-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rawshark-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tshark-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-1.10.10-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"wireshark-tools-1.10.10-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
