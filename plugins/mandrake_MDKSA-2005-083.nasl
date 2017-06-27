#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:083. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18237);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/08/09 10:54:12 $");

  script_cve_id("CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
  script_xref(name:"MDKSA", value:"2005:083");

  script_name(english:"Mandrake Linux Security Advisory : ethereal (MDKSA-2005:083)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered in previous version of
Ethereal that have been fixed in the 0.10.11 release, including :

  - The ANSI A and DHCP dissectors are vulnerable to format
    string vulnerabilities.

  - The DISTCC, FCELS, SIP, ISIS, CMIP, CMP, CMS, CRMF, ESS,
    OCSP, PKIX1Explitit, PKIX Qualified, X.509, Q.931,
    MEGACO, NCP, ISUP, TCAP and Presentation dissectors are
    vulnerable to buffer overflows.

  - The KINK, WSP, SMB Mailslot, H.245, MGCP, Q.931, RPC,
    GSM and SMB NETLOGON dissectors are vulnerable to
    pointer handling errors.

  - The LMP, KINK, MGCP, RSVP, SRVLOC, EIGRP, MEGACO, DLSw,
    NCP and L2TP dissectors are vulnerable to looping
    problems.

  - The Telnet and DHCP dissectors could abort.

  - The TZSP, Bittorrent, SMB, MGCP and ISUP dissectors
    could cause a segmentation fault.

  - The WSP, 802.3 Slow protocols, BER, SMB Mailslot, SMB,
    NDPS, IAX2, RADIUS, SMB PIPE, MRDISC and TCAP dissectors
    could throw assertions.

  - The DICOM, NDPS and ICEP dissectors are vulnerable to
    memory handling errors.

  - The GSM MAP, AIM, Fibre Channel,SRVLOC, NDPS, LDAP and
    NTLMSSP dissectors could terminate abnormallly."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00019.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"ethereal-0.10.11-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ethereal-tools-0.10.11-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ethereal0-0.10.11-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libethereal0-0.10.11-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tethereal-0.10.11-0.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"ethereal-0.10.11-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"ethereal-tools-0.10.11-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64ethereal0-0.10.11-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libethereal0-0.10.11-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tethereal-0.10.11-0.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
