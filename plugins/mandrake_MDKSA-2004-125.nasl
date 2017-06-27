#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:125. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15636);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0986");
  script_xref(name:"MDKSA", value:"2004:125");

  script_name(english:"Mandrake Linux Security Advisory : iptables (MDKSA-2004:125)");
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
"Faheem Mitha discovered that the iptables tool would not always load
the required modules on its own as it should have, which could in turn
lead to firewall rules not being loaded on system startup in some
cases.

The updated packages are patched to prevent this problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected iptables, iptables-devel and / or iptables-ipv6
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables-ipv6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/05");
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
if (rpm_check(release:"MDK10.0", reference:"iptables-1.2.9-5.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"iptables-ipv6-1.2.9-5.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"iptables-1.2.9-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"iptables-devel-1.2.9-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"iptables-ipv6-1.2.9-7.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"iptables-1.2.8-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"iptables-ipv6-1.2.8-2.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
