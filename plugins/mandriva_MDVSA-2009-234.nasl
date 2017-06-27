#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:234. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(40997);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:52:21 $");

  script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051", "CVE-2009-3163");
  script_bugtraq_id(36194);
  script_xref(name:"MDVSA", value:"2009:234-2");

  script_name(english:"Mandriva Linux Security Advisory : silc-toolkit (MDVSA-2009:234-2)");
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

The silc_asn1_encoder function in lib/silcasn1/silcasn1_encode.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.8 allows
remote attackers to overwrite a stack location and possibly execute
arbitrary code via a crafted OID value, related to incorrect use of a
%lu format string (CVE-2008-7159).

The silc_http_server_parse function in lib/silchttp/silchttpserver.c
in the internal HTTP server in silcd in Secure Internet Live
Conferencing (SILC) Toolkit before 1.1.9 allows remote attackers to
overwrite a stack location and possibly execute arbitrary code via a
crafted Content-Length header, related to incorrect use of a %lu
format string (CVE-2008-7160).

Multiple format string vulnerabilities in lib/silcclient/command.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10, and
SILC Client 1.1.8 and earlier, allow remote attackers to execute
arbitrary code via format string specifiers in a channel name, related
to (1) silc_client_command_topic, (2) silc_client_command_kick, (3)
silc_client_command_leave, and (4) silc_client_command_users
(CVE-2009-3163).

This update provides a solution to these vulnerabilities.

Update :

Packages for MES5 was not provided previousely, this update addresses
this problem.

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silc-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silcclient-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilc-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilcclient-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64silc-1.1_2-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64silcclient-1.1_2-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsilc-1.1_2-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsilcclient-1.1_2-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"silc-toolkit-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"silc-toolkit-devel-1.1.2-2.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
