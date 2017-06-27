#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:204. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24589);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-5794");
  script_bugtraq_id(20956);
  script_xref(name:"MDKSA", value:"2006:204");

  script_name(english:"Mandrake Linux Security Advisory : openssh (MDKSA-2006:204)");
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
"A vulnerability in the privilege separation functionality in OpenSSH
was discovered, caused by an incorrect checking for bad signatures in
sshd's privsep monitor. As a result, the monitor and the unprivileged
process can get out sync. The OpenSSH team indicated that this bug is
not known to be exploitable in the abence of additional
vulnerabilities.

Updated packages have been patched to correct this issue, and Mandriva
Linux 2007 has received the latest version of OpenSSH."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/release-4.5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"openssh-4.3p1-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-askpass-4.3p1-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-askpass-gnome-4.3p1-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-clients-4.3p1-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-server-4.3p1-0.4.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"openssh-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-common-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-gnome-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-clients-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-server-4.5p1-0.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
