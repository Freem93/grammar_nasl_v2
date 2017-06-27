#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:013. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16241);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/08/09 10:54:12 $");

  script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");
  script_xref(name:"MDKSA", value:"2005:013");

  script_name(english:"Mandrake Linux Security Advisory : ethereal (MDKSA-2005:013)");
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
"A number of vulnerabilities were found in Ethereal, all of which are
fixed in version 0.10.9: The COPS dissector could go into an infinite
loop (CVE-2005-0006); the DLSw dissector could cause an assertion,
making Ethereal exit prematurely (CVE-2005-0007); the DNP dissector
could cause memory corruption (CVE-2005-0008); the Gnutella dissector
could cause an assertion, making Ethereal exit prematurely
(CVE-2005-0009); the MMSE dissector could free static memory
(CVE-2005-0010); and the X11 protocol dissector is vulnerable to a
string buffer overflow (CVE-2005-0084)."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00017.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/25");
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
if (rpm_check(release:"MDK10.0", reference:"ethereal-0.10.9-0.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"ethereal-0.10.9-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ethereal-tools-0.10.9-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ethereal0-0.10.9-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libethereal0-0.10.9-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tethereal-0.10.9-0.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
