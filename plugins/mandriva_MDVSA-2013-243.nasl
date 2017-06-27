#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:243. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(70185);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-4288", "CVE-2013-4325", "CVE-2013-4326", "CVE-2013-4327");
  script_bugtraq_id(62499, 62503, 62505, 62511);
  script_xref(name:"MDVSA", value:"2013:243");

  script_name(english:"Mandriva Linux Security Advisory : polkit (MDVSA-2013:243)");
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
"Updated polkit packages fix security vulnerability :

A race condition was found in the way the PolicyKit pkcheck utility
checked process authorization when the process was specified by its
process ID via the --process option. A local user could use this flaw
to bypass intended PolicyKit authorizations and escalate their
privileges (CVE-2013-4288).

Note: Applications that invoke pkcheck with the --process option need
to be modified to use the pid,pid-start-time,uid argument for that
option, to allow pkcheck to check process authorization correctly.

Because of the change in the PolicyKit API, hplip (CVE-2013-4325),
rtkit (CVE-2013-4326), and systemd (CVE-2013-4327) packages have been
updated to use a different API that is not affected by this PolicyKit
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mageia.org/show_bug.cgi?id=11260"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64polkit-gir1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64polkit1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64polkit1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sane-hpaio1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-daemon0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-id1280");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-id1280-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-journal0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64systemd-login0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:polkit-desktop-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:systemd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:systemd-units");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-doc-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-ppds-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-model-data-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-devel-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64polkit-gir1.0-0.104-6.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64polkit1-devel-0.104-6.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64polkit1_0-0.104-6.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sane-hpaio1-3.12.4-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-daemon0-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-daemon0-devel-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-id1280-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-id1280-devel-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-journal0-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-journal0-devel-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-login0-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64systemd-login0-devel-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"polkit-0.104-6.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"polkit-desktop-policy-0.104-6.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rtkit-0.10-3.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"systemd-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"systemd-sysvinit-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"systemd-tools-44-16.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"systemd-units-44-16.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
