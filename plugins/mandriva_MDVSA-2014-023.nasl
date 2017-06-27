#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:023. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72135);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/28 11:43:33 $");

  script_cve_id("CVE-2013-6402", "CVE-2013-6427");
  script_bugtraq_id(63959, 64131);
  script_xref(name:"MDVSA", value:"2014:023");

  script_name(english:"Mandriva Linux Security Advisory : hplip (MDVSA-2014:023)");
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
"Updated hplip packages fix security vulnerabilities :

It was discovered that the HPLIP Polkit daemon incorrectly handled
temporary files. A local attacker could possibly use this issue to
overwrite arbitrary files (CVE-2013-6402).

It was discovered that HPLIP contained an upgrade tool that would
download code in an unsafe fashion. If a remote attacker were able to
perform a man-in-the-middle attack, this flaw could be exploited to
execute arbitrary code (CVE-2013-6427)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725876"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-hpijs-ppds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-model-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hpip0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hpip0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sane-hpaio1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-doc-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-ppds-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-model-data-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-devel-3.12.4-1.3.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sane-hpaio1-3.12.4-1.3.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
