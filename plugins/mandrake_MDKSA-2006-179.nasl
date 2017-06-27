#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:179. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24565);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2006-4924", "CVE-2006-4925", "CVE-2006-5051", "CVE-2008-4109");
  script_bugtraq_id(20216, 20241);
  script_xref(name:"MDKSA", value:"2006:179");

  script_name(english:"Mandrake Linux Security Advisory : openssh (MDKSA-2006:179)");
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
"Tavis Ormandy of the Google Security Team discovered a Denial of
Service vulnerability in the SSH protocol version 1 CRC compensation
attack detector. This could allow a remote unauthenticated attacker to
trigger excessive CPU utilization by sending a specially crafted SSH
message, which would then deny ssh services to other users or
processes (CVE-2006-4924, CVE-2006-4925). Please note that Mandriva
ships with only SSH protocol version 2 enabled by default.

Next, an unsafe signal handler was found by Mark Dowd. This signal
handler was vulnerable to a race condition that could be exploited to
perform a pre-authentication DoS, and theoretically a
pre-authentication remote code execution in the case where some
authentication methods like GSSAPI are enabled (CVE-2006-5051).

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"openssh-4.3p1-0.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-askpass-4.3p1-0.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-askpass-gnome-4.3p1-0.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-clients-4.3p1-0.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssh-server-4.3p1-0.3.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"openssh-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-common-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-askpass-gnome-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-clients-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"openssh-server-4.3p2-12.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
