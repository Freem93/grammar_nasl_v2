#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:091. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14073);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0690", "CVE-2003-0692");
  script_xref(name:"MDKSA", value:"2003:091");

  script_name(english:"Mandrake Linux Security Advisory : kdebase (MDKSA-2003:091)");
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
"A vulnerability was discovered in all versions of KDE 2.2.0 up to and
including 3.1.3. KDM does not check for successful completion of the
pam_setcred() call and in the case of error conditions in the
installed PAM modules, KDM may grant local root access to any user
with valid login credentials. It has been reported to the KDE team
that a certain configuration of the MIT pam_krb5 module can result in
a failing pam_setcred() call which leaves the session alive and would
provide root access to any regular user. It is also possible that this
vulnerability can likewise be exploited with other PAM modules in a
similar manner.

Another vulnerability was discovered in kdm where the cookie session
generating algorithm was considered too weak to supply a full 128 bits
of entropy. This allowed unauthorized users to brute-force the session
cookie.

mdkkdm, a specialized version of kdm, is likewise vulnerable to these
problems and has been patched as well."
  );
  # http://cert.uni-stuttgart.de/archive/suse/security/2002/12/msg00101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6542c24b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20030916-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mdkkdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/16");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-3.0.5a-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-devel-3.0.5a-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-nsplugins-3.0.5a-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdebase-3.1-83.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdebase-devel-3.1-83.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdebase-kdm-3.1-83.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdebase-nsplugins-3.1-83.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"mdkkdm-9.1-24.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
