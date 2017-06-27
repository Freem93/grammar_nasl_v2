#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:078. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37259);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2009-0547",
    "CVE-2009-0582",
    "CVE-2009-0587"
  );
  script_bugtraq_id(
    33720,
    34100,
    34109
  );
  script_osvdb_id(
    52673,
    52701,
    52702,
    52703
  );
  script_xref(name:"MDVSA", value:"2009:078");

  script_name(english:"Mandriva Linux Security Advisory : evolution-data-server (MDVSA-2009:078)");
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
"A wrong handling of signed Secure/Multipurpose Internet Mail
Extensions (S/MIME) e-mail messages enables attackers to spoof its
signatures by modifying the latter copy (CVE-2009-0547).

Crafted authentication challange packets (NT Lan Manager type 2) sent
by a malicious remote mail server enables remote attackers either to
cause denial of service and to read information from the process
memory of the client (CVE-2009-0582).

Multiple integer overflows in Base64 encoding functions enables
attackers either to cause denial of service and to execute arbitrary
code (CVE-2009-0587).

This update provides fixes for those vulnerabilities.

Update :

evolution-data-server packages from Mandriva Linux distributions
2008.1 and 2009.0 are not affected by CVE-2009-0587."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel-provider10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel-provider11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ebackend0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ebook9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecal7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edata-book2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edata-cal6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserverui8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64egroupwise13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exchange-storage3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdata1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel-provider10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel-provider11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libebackend0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libebook9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecal7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedata-book2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedata-cal6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserverui8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libegroupwise13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexchange-storage3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdata1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"evolution-data-server-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64camel-provider10-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64camel10-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ebook9-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ecal7-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64edata-book2-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64edata-cal6-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64edataserver-devel-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64edataserver9-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64edataserverui8-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64egroupwise13-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64exchange-storage3-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcamel-provider10-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcamel10-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libebook9-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libecal7-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libedata-book2-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libedata-cal6-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libedataserver-devel-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libedataserver9-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libedataserverui8-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libegroupwise13-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libexchange-storage3-1.12.2-1.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"evolution-data-server-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64camel-provider11-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64camel11-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64ebook9-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64ecal7-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64edata-book2-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64edata-cal6-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64edataserver-devel-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64edataserver9-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64edataserverui8-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64egroupwise13-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64exchange-storage3-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64gdata1-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libcamel-provider11-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libcamel11-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libebook9-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libecal7-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libedata-book2-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libedata-cal6-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libedataserver-devel-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libedataserver9-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libedataserverui8-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libegroupwise13-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libexchange-storage3-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libgdata1-2.22.3-1.2mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"evolution-data-server-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64camel14-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ebackend0-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ebook9-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ecal7-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64edata-book2-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64edata-cal6-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64edataserver-devel-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64edataserver11-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64edataserverui8-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64egroupwise13-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64exchange-storage3-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64gdata1-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libcamel14-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libebackend0-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libebook9-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libecal7-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libedata-book2-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libedata-cal6-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libedataserver-devel-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libedataserver11-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libedataserverui8-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libegroupwise13-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libexchange-storage3-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libgdata1-2.24.2-2.2mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
