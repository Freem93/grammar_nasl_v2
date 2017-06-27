#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:235. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48152);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:11:05 $");

  script_cve_id("CVE-2009-3051", "CVE-2009-3163");
  script_xref(name:"MDVSA", value:"2009:235");

  script_name(english:"Mandriva Linux Security Advisory : silc-toolkit (MDVSA-2009:235)");
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
"Multiple vulnerabilities was discovered and corrected in 
silc-toolkit :

Multiple format string vulnerabilities in
lib/silcclient/client_entry.c in Secure Internet Live Conferencing
(SILC) Toolkit before 1.1.10, and SILC Client before 1.1.8, allow
remote attackers to execute arbitrary code via format string
specifiers in a nickname field, related to the (1)
silc_client_add_client, (2) silc_client_update_client, and (3)
silc_client_nickname_format functions (CVE-2009-3051).

Multiple format string vulnerabilities in lib/silcclient/command.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10, and
SILC Client 1.1.8 and earlier, allow remote attackers to execute
arbitrary code via format string specifiers in a channel name, related
to (1) silc_client_command_topic, (2) silc_client_command_kick, (3)
silc_client_command_leave, and (4) silc_client_command_users
(CVE-2009-3163).

This update provides a solution to these vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silc1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silcclient1.1_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilc1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilcclient1.1_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64silc1.1_2-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64silcclient1.1_3-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsilc1.1_2-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsilcclient1.1_3-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"silc-toolkit-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"silc-toolkit-devel-1.1.9-1.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
