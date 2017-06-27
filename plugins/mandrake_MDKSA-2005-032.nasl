#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:032. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16375);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-1999-1572");
  script_xref(name:"MDKSA", value:"2005:032-1");

  script_name(english:"Mandrake Linux Security Advisory : cpio (MDKSA-2005:032-1)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability in cpio was discovered where cpio would create world-
writeable files when used in -o/--create mode and giving an output
file (with -O). This would allow any user to modify the created cpio
archive. The updated packages have been patched so that cpio now
respects the current umask setting of the user.

Update :

The updated cpio packages for 10.1, while they would install with
urpmi on the commandline, would not install via rpmdrake. The updated
packages correct that."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"cpio-2.5-4.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
