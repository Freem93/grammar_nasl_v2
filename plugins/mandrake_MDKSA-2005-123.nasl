#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:123. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19267);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-2317");
  script_xref(name:"MDKSA", value:"2005:123");

  script_name(english:"Mandrake Linux Security Advisory : shorewall (MDKSA-2005:123)");
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
"A vulnerability was discovered in all versions of shorewall where a
client accepted by MAC address filtering is able to bypass any other
rule. If MACLIST_TTL is set to a value greater than 0 or
MACLIST_DISPOSITION is set to ACCEPT in shorewall.conf, and a client
is positively identified through its MAC address, it bypasses all
other policies and rules in place, gaining access to all open services
on the firewall.

Shorewall 2.0.17 is provided which fixes this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://shorewall.net/News.htm#20050717"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shorewall and / or shorewall-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:shorewall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:shorewall-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"shorewall-2.0.17-1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"shorewall-2.0.17-1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"shorewall-doc-2.0.17-1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"shorewall-doc-2.0.17-1.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"shorewall-2.0.17-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"shorewall-2.0.17-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"shorewall-doc-2.0.17-1.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"shorewall-doc-2.0.17-1.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"shorewall-2.0.17-1.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"shorewall-2.0.17-1.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"shorewall-doc-2.0.17-1.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"shorewall-doc-2.0.17-1.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
