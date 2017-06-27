#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:004. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72019);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/20 00:39:07 $");

  script_cve_id("CVE-2013-7108", "CVE-2013-7205");
  script_bugtraq_id(64363, 64489);
  script_xref(name:"MDVSA", value:"2014:004");

  script_name(english:"Mandriva Linux Security Advisory : nagios (MDVSA-2014:004)");
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
"Multiple vulnerabilities has been discovered and corrected in nagios :

Multiple off-by-one errors in Nagios Core 3.5.1, 4.0.2, and earlier,
and Icinga before 1.8.5, 1.9 before 1.9.4, and 1.10 before 1.10.2
allow remote authenticated users to obtain sensitive information from
process memory or cause a denial of service (crash) via a long string
in the last key value in the variable list to the process_cgivars
function in (1) avail.c, (2) cmd.c, (3) config.c, (4) extinfo.c, (5)
histogram.c, (6) notifications.c, (7) outages.c, (8) status.c, (9)
statusmap.c, (10) summary.c, and (11) trends.c in cgi/, which triggers
a heap-based buffer over-read (CVE-2013-7108).

Off-by-one error in the process_cgivars function in
contrib/daemonchk.c in Nagios Core 3.5.1, 4.0.2, and earlier allows
remote authenticated users to obtain sensitive information from
process memory or cause a denial of service (crash) via a long string
in the last key value in the variable list, which triggers a
heap-based buffer over-read (CVE-2013-7205).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios, nagios-devel and / or nagios-www packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nagios-www");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nagios-3.4.4-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nagios-devel-3.4.4-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nagios-www-3.4.4-4.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
