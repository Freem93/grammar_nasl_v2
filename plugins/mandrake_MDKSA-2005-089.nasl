#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:089. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18305);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2002-0137", "CVE-2002-0138");
  script_xref(name:"MDKSA", value:"2005:089");

  script_name(english:"Mandrake Linux Security Advisory : cdrdao (MDKSA-2005:089)");
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
"The cdrdao package contains two vulnerabilities; the first allows
local users to read arbitrary files via the show-data command and the
second allows local users to overwrite arbitrary files via a symlink
attack on the ~/.cdrdao configuration file. This can also lead to
elevated privileges (a root shell) due to cdrdao being installed suid
root.

The provided packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cdrdao and / or cdrdao-gcdmaster packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrdao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cdrdao-gcdmaster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
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
if (rpm_check(release:"MDK10.0", reference:"cdrdao-1.1.8-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"cdrdao-gcdmaster-1.1.8-2.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"cdrdao-1.1.9-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"cdrdao-gcdmaster-1.1.9-6.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"cdrdao-1.1.9-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cdrdao-gcdmaster-1.1.9-7.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
