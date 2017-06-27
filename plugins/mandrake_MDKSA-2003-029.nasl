#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:029. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14013);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/31 23:47:33 $");

  script_cve_id("CVE-2003-0033");
  script_xref(name:"MDKSA", value:"2003:029");

  script_name(english:"Mandrake Linux Security Advisory : snort (MDKSA-2003:029)");
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
"A buffer overflow was discovered in the snort RPC normalization
routines by ISS-XForce which can cause snort to execute arbitrary code
embedded within sniffed network packets. The rpc_decode preprocessor
is enabled by default. The snort developers have released version
1.9.1 to correct this behaviour; snort versions from 1.8 up to 1.9.0
are vulnerable.

For those unable to upgrade, you can disable the rpc_decode
preprocessor by commenting out the line (place a '#' character at the
beginning of the line) that enables it in your snort.conf file :

preprocessor rpc_decode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?oid=21951"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-bloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-plain+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-snmp+flexresp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-bloat-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-mysql-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-mysql+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-plain+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-postgresql-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-postgresql+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-snmp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-snmp+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-bloat-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-mysql-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-mysql+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-plain+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-postgresql-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-postgresql+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-snmp-1.9.1-0.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-snmp+flexresp-1.9.1-0.5mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
