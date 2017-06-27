#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:157. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19912);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-2851");
  script_xref(name:"MDKSA", value:"2005:157");

  script_name(english:"Mandrake Linux Security Advisory : smb4k (MDKSA-2005:157)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A severe security issue has been discovered in Smb4K. By linking a
simple text file FILE to /tmp/smb4k.tmp or /tmp/sudoers, an attacker
could get access to the full contents of the /etc/super.tab or
/etc/sudoers file, respectively, because Smb4K didn't check for the
existance of these files before writing any contents. When using
super, the attack also resulted in /etc/super.tab being a symlink to
FILE.

Affected are all versions of the 0.4, 0.5, and 0.6 series of Smb4K.

The updated packages have been patched to correct this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://smb4k.berlios.de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected smb4k package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:smb4k");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
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
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"smb4k-0.4.0-3.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"smb4k-0.5.1-1.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
