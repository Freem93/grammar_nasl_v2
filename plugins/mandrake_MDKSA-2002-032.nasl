#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:032. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13938);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2001-1279");
  script_xref(name:"MDKSA", value:"2002:032");

  script_name(english:"Mandrake Linux Security Advisory : tcpdump (MDKSA-2002:032)");
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
"Several buffer overflows were found in the tcpdump package by FreeBSD
developers during a code audit, in versions prior to 3.5. However,
newer versions of tcpdump, including 3.6.2, are also vulnerable to
another buffer overflow in the AFS RPC decoding functions, which was
discovered by Nick Cleaton. These vulnerabilities could be used by a
remote attacker to crash the the tcpdump process or possibly even be
exploited to execute arbitrary code as the user running tcpdump, which
is usually root.

The newer libpcap 0.6 has also been audited to make it more safe by
implementing better buffer boundary checks in several functions."
  );
  # ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-01:48.tcpdump.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a0a3b08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ciac.org/ciac/bulletins/l-015.shtml"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpcap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpcap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpcap0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/16");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"libpcap-0.6.2-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"libpcap-devel-0.6.2-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tcpdump-3.6.2-2.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"libpcap-0.6.2-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"libpcap-devel-0.6.2-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tcpdump-3.6.2-2.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libpcap0-0.6.2-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libpcap0-devel-0.6.2-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tcpdump-3.6.2-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tcpdump-3.6.2-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"tcpdump-3.6.2-2.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
