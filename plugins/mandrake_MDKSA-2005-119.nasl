#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:119. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19201);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
  script_xref(name:"CERT", value:"259798");
  script_xref(name:"CERT", value:"623332");
  script_xref(name:"CERT", value:"885830");
  script_xref(name:"MDKSA", value:"2005:119");

  script_name(english:"Mandrake Linux Security Advisory : krb5 (MDKSA-2005:119)");
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
"A number of vulnerabilities have been corrected in this Kerberos
update :

The rcp protocol would allow a server to instruct a client to write to
arbitrary files outside of the current directory. The Kerberos-aware
rcp could be abused to copy files from a malicious server
(CVE-2004-0175).

Gael Delalleau discovered an information disclosure vulnerability in
the way some telnet clients handled messages from a server. This could
be abused by a malicious telnet server to collect information from the
environment of any victim connecting to the server using the Kerberos-
aware telnet client (CVE-2005-0488).

Daniel Wachdorf disovered that in error conditions that could occur in
response to correctly-formatted client requests, the Kerberos 5 KDC
may attempt to free uninitialized memory, which could cause the KDC to
crash resulting in a Denial of Service (CVE-2005-1174).

Daniel Wachdorf also discovered a single-byte heap overflow in the
krb5_unparse_name() function that could, if successfully exploited,
lead to a crash, resulting in a DoS. To trigger this flaw, an attacker
would need to have control of a Kerberos realm that shares a cross-
realm key with the target (CVE-2005-1175).

Finally, a double-free flaw was discovered in the krb5_recvauth()
routine which could be triggered by a remote unauthenticated attacker.
This issue could potentially be exploited to allow for the execution
of arbitrary code on a KDC. No exploit is currently known to exist
(CVE-2005-1689).

The updated packages have been patched to address this issue and
Mandriva urges all users to upgrade to these packages as quickly as
possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-002-kdc.txt"
  );
  # http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-003-recvauth.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20d6a900"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-server-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"ftp-client-krb5-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ftp-server-krb5-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-server-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-workstation-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-devel-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-devel-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-client-krb5-1.3-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-server-krb5-1.3-6.6.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"ftp-client-krb5-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ftp-server-krb5-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"krb5-server-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"krb5-workstation-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64krb53-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64krb53-devel-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkrb53-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkrb53-devel-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"telnet-client-krb5-1.3.4-2.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"telnet-server-krb5-1.3.4-2.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"ftp-client-krb5-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"ftp-server-krb5-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"krb5-server-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"krb5-workstation-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64krb53-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64krb53-devel-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkrb53-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkrb53-devel-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"telnet-client-krb5-1.3.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"telnet-server-krb5-1.3.6-6.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
