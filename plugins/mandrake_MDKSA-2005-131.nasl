#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:131. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19891);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2362", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
  script_bugtraq_id(14399);
  script_xref(name:"MDKSA", value:"2005:131");

  script_name(english:"Mandrake Linux Security Advisory : ethereal (MDKSA-2005:131)");
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
"A number of vulnerabilities were discovered in versions of Ethereal
prior to version 0.10.12, including :

The SMB dissector could overflow a buffer or exhaust memory
(CVE-2005-2365).

iDefense discovered that several dissectors are vulnerable to format
string overflows (CVE-2005-2367).

A number of other portential crash issues in various dissectors have
also been corrected.

This update provides Ethereal 0.10.12 which is not vulnerable to these
issues."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00020.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"ethereal-0.10.12-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ethereal-tools-0.10.12-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ethereal0-0.10.12-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libethereal0-0.10.12-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tethereal-0.10.12-0.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"ethereal-0.10.12-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"ethereal-tools-0.10.12-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64ethereal0-0.10.12-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libethereal0-0.10.12-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tethereal-0.10.12-0.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
