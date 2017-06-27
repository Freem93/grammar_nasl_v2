#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:074. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14172);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/12/05 14:06:23 $");

  script_cve_id("CVE-2004-0582", "CVE-2004-0583");
  script_xref(name:"MDKSA", value:"2004:074");

  script_name(english:"Mandrake Linux Security Advisory : webmin (MDKSA-2004:074)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Unknown vulnerability in Webmin 1.140 allows remote attackers to
bypass access control rules and gain read access to configuration
information for a module. (CVE-2004-0582)

The account lockout functionality in Webmin 1.140 does not parse
certain character strings, which allows remote attackers to conduct a
brute-force attack to guess user IDs and passwords. (CVE-2004-0583)

The updated packages are patched to correct the problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/27");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"webmin-1.121-4.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"webmin-1.121-4.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", reference:"webmin-1.070-1.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"webmin-1.100-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"webmin-1.100-3.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
