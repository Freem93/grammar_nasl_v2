#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:101. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38204);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2009-0146",
    "CVE-2009-0147",
    "CVE-2009-0165",
    "CVE-2009-0166",
    "CVE-2009-0799",
    "CVE-2009-0800",
    "CVE-2009-1179",
    "CVE-2009-1180",
    "CVE-2009-1181",
    "CVE-2009-1182",
    "CVE-2009-1183"
  );
  script_bugtraq_id(34568);
  script_osvdb_id(
    54465,
    54469,
    54472,
    54477,
    54480,
    54483,
    54486,
    54489,
    54496,
    54496,
    54497
  );
  script_xref(name:"MDVSA", value:"2009:101");

  script_name(english:"Mandriva Linux Security Advisory : xpdf (MDVSA-2009:101)");
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
"Multiple buffer overflows in the JBIG2 decoder allows remote attackers
to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0146).

Multiple integer overflows in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0147).

An integer overflow in the JBIG2 decoder has unspecified impact.
(CVE-2009-0165).

A free of uninitialized memory flaw in the the JBIG2 decoder allows
remote to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0166).

Multiple input validation flaws in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF file
(CVE-2009-0800).

An out-of-bounds read flaw in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0799).

An integer overflow in the JBIG2 decoder allows remote attackers to
execute arbitrary code via a crafted PDF file (CVE-2009-1179).

A free of invalid data flaw in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF (CVE-2009-1180).

A NULL pointer dereference flaw in the JBIG2 decoder allows remote
attackers to cause denial of service (crash) via a crafted PDF file
(CVE-2009-1181).

Multiple buffer overflows in the JBIG2 MMR decoder allows remote
attackers to cause denial of service or to execute arbitrary code via
a crafted PDF file (CVE-2009-1182, CVE-2009-1183).

This update provides fixes for that vulnerabilities."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xpdf, xpdf-common and / or xpdf-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/29");
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
if (rpm_check(release:"MDK2008.0", reference:"xpdf-3.02-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xpdf-common-3.02-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xpdf-tools-3.02-8.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"xpdf-3.02-10.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xpdf-common-3.02-10.1mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"xpdf-3.02-12.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xpdf-common-3.02-12.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
