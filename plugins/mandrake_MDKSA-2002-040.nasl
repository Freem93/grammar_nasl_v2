#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:040. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13944);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-0639", "CVE-2002-0640");
  script_xref(name:"MDKSA", value:"2002:040-1");

  script_name(english:"Mandrake Linux Security Advisory : openssh (MDKSA-2002:040-1)");
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
"An input validation error exists in the OpenSSH server between
versions 2.3.1 and 3.3 that can result in an integer overflow and
privilege escalation. This error is found in the
PAMAuthenticationViaKbdInt code in versions 2.3.1 to 3.3, and the
ChallengeResponseAuthentication code in versions 2.9.9 to 3.3. OpenSSH
3.4 and later are not affected, and OpenSSH 3.2 and later prevent
privilege escalation if UsePrivilegeSeparation is enabled; in OpenSSH
3.3 and higher this is the default behaviour of OpenSSH.

To protect yourself, users should be using OpenSSH 3.3 with
UsePrivilegeSeparation enabled (see MDKSA:2002-040). However, it is
highly recommended that all Mandrake Linux users upgrade to version
3.4 which corrects these errors.

There are a few caveats with this upgrade, however, that users should
be aware of :

  - On Linux kernel 2.2 (the default for Mandrake Linux
    7.x), the use of Compression and UsePrivilegeSeparation
    are mutually exclusive. You can use one feature or the
    other, not both; we recommend disabling Compression and
    using privsep until this can be resolved.

  - Using privsep may cause some PAM modules which expect to
    run with root privilege to fail. For instance, users
    will not be able to change their password if they
    attempt to log into an account with an expired password.

If you absolutely must use one of these features that conflict with
privsep, you can disable it in /etc/ssh/sshd_config by using :

UsePrivilegeSeparation no

However, if you do this, be sure you are running OpenSSH 3.4. Updates
to OpenSSH will be made available once these problems are resolved."
  );
  # http://marc.theaimsgroup.com/?l=openssh-unix-dev&m=102495293705094&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=openssh-unix-dev&m=102495293705094&w=2"
  );
  # http://online.securityfocus.com/archive/1/280070/2002-06-29/2002-07-05/0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99fdbe8b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/02");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssh-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssh-askpass-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssh-askpass-gnome-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssh-clients-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssh-server-3.4p1-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssh-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssh-askpass-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssh-askpass-gnome-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssh-clients-3.4p1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssh-server-3.4p1-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssh-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssh-askpass-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssh-askpass-gnome-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssh-clients-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssh-server-3.4p1-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssh-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssh-askpass-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssh-askpass-gnome-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssh-clients-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssh-server-3.4p1-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssh-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssh-askpass-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssh-askpass-gnome-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssh-clients-3.4p1-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssh-server-3.4p1-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
