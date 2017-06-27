#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:040. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13860);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-0406");
  script_xref(name:"MDKSA", value:"2001:040-1");

  script_name(english:"Mandrake Linux Security Advisory : samba (MDKSA-2001:040-1)");
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
"A vulnerability found by Marcus Meissner exists in Samba where it was
not creating temporary files safely which could allow local users to
overwrite files that they may not have access to. This happens when a
remote user queried a printer queue and samba would create a temporary
file in which the queue's data was written. Because Samba created the
file insecurely and used a predictable filename, a local attacker
could cause Samba to overwrite files that the attacker did not have
access to. As well, the smbclient 'more' and 'mput' commands also
created temporary files insecurely.

The vulnerability is present in Samba 2.0.7 and lower. 2.0.8 and 2.2.0
correct this behaviour.

Update :

The Samba 2.0.8 release did not entirely fix the temporary file issues
in previous versions. The Samba team released 2.0.9 recently which
does fix these problems completely. As well, the 8.0 packages will now
not attempt to use /root/tmp as the temporary directory, but /var/tmp."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected samba, samba-client and / or samba-common
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/05/21");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"samba-2.0.9-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"samba-client-2.0.9-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"samba-common-2.0.9-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"samba-2.0.9-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"samba-client-2.0.9-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"samba-common-2.0.9-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-2.0.9-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-client-2.0.9-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-common-2.0.9-1.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
