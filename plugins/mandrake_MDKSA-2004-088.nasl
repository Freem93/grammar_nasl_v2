#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:088. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14673);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
  script_xref(name:"CERT", value:"350792");
  script_xref(name:"CERT", value:"550464");
  script_xref(name:"CERT", value:"795632");
  script_xref(name:"CERT", value:"866472");
  script_xref(name:"MDKSA", value:"2004:088");

  script_name(english:"Mandrake Linux Security Advisory : krb5 (MDKSA-2004:088)");
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
"A double-free vulnerability exists in the MIT Kerberos 5's KDC program
that could potentially allow a remote attacker to execute arbitrary
code on the KDC host. As well, multiple double-free vulnerabilities
exist in the krb5 library code, which makes client programs and
application servers vulnerable. The MIT Kerberos 5 development team
believes that exploitation of these bugs would be difficult and no
known vulnerabilities are believed to exist. The vulnerability in
krb524d was discovered by Marc Horowitz; the other double-free
vulnerabilities were discovered by Will Fiveash and Nico Williams at
Sun.

Will Fiveash and Nico Williams also found another vulnerability in the
ASN.1 decoder library. This makes krb5 vulnerable to a DoS (Denial of
Service) attack causing an infinite loop in the decoder. The KDC is
vulnerable to this attack.

The MIT Kerberos 5 team has provided patches which have been applied
to the updated software to fix these issues. Mandrakesoft encourages
all users to upgrade immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-002-dblfree.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-003-asn1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-server-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"ftp-client-krb5-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ftp-server-krb5-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-server-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-workstation-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-devel-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-devel-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-client-krb5-1.3-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-server-krb5-1.3-6.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"ftp-client-krb5-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"ftp-server-krb5-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-devel-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-libs-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-server-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-workstation-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"telnet-client-krb5-1.2.7-1.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"telnet-server-krb5-1.2.7-1.4.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"ftp-client-krb5-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ftp-server-krb5-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"krb5-server-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"krb5-workstation-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64krb51-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64krb51-devel-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkrb51-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkrb51-devel-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"telnet-client-krb5-1.3-3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"telnet-server-krb5-1.3-3.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
