#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:006. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14106);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
  script_xref(name:"MDKSA", value:"2004:006-1");

  script_name(english:"Mandrake Linux Security Advisory : gaim (MDKSA-2004:006-1)");
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
"A number of vulnerabilities were discovered in the gaim instant
messenger program by Steffan Esser, versions 0.75 and earlier. Thanks
to Jacques A. Vidrine for providing initial patches.

Multiple buffer overflows exist in gaim 0.75 and earlier: When parsing
cookies in a Yahoo web connection; YMSG protocol overflows parsing the
Yahoo login webpage; a YMSG packet overflow; flaws in the URL parser;
and flaws in the HTTP Proxy connect (CAN-2004-006).

A buffer overflow in gaim 0.74 and earlier in the Extract Info Field
Function used for MSN and YMSG protocol handlers (CAN-2004-007).

An integer overflow in gaim 0.74 and earlier, when allocating memory
for a directIM packet results in a heap overflow (CVE-2004-0008).

Update :

The patch used to correct the problem was slightly malformed and could
cause an infinite loop and crash with the Yahoo protocol. The new
packages have a corrected patch that resolves the problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-encrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-festival");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/30");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"gaim-0.75-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"gaim-encrypt-0.75-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libgaim-remote0-0.75-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libgaim-remote0-devel-0.75-1.2.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"gaim-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"gaim-encrypt-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"gaim-festival-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"gaim-perl-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gaim-remote0-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gaim-remote0-devel-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgaim-remote0-0.75-1.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgaim-remote0-devel-0.75-1.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
