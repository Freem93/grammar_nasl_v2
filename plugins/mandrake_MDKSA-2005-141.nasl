#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:141. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19898);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2005-2549", "CVE-2005-2550");
  script_bugtraq_id(14532);
  script_xref(name:"MDKSA", value:"2005:141");

  script_name(english:"Mandrake Linux Security Advisory : evolution (MDKSA-2005:141)");
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
"Multiple format string vulnerabilities in Evolution 1.5 through
2.3.6.1 allow remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via (1) full vCard data, (2)
contact data from remote LDAP servers, or (3) task list data from
remote servers. (CVE-2005-2549)

A format string vulnerability in Evolution 1.4 through 2.3.6.1 allows
remote attackers to cause a denial of service (crash) and possibly
execute arbitrary code via the calendar entries such as task lists,
which are not properly handled when the user selects the Calendars
tab. (CVE-2005-2550)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected evolution, evolution-devel and / or
evolution-pilot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-pilot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/17");
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
if (rpm_check(release:"MDK10.1", reference:"evolution-2.0.3-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"evolution-devel-2.0.3-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"evolution-pilot-2.0.3-1.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"evolution-2.0.4-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"evolution-devel-2.0.4-3.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"evolution-pilot-2.0.4-3.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
