#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:049. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17278);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2005-0208", "CVE-2005-0472", "CVE-2005-0473");
  script_xref(name:"MDKSA", value:"2005:049");

  script_name(english:"Mandrake Linux Security Advisory : gaim (MDKSA-2005:049)");
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
"Gaim versions prior to version 1.1.4 suffer from a few security issues
such as the HTML parses not sufficiently validating its input. This
allowed a remote attacker to crash the Gaim client be sending certain
malformed HTML messages (CVE-2005-0208 and CVE-2005-0473).

As well, insufficient input validation was also discovered in the
'Oscar' protocol handler, used for ICQ and AIM. By sending specially
crafted packets, remote users could trigger an inifinite loop in Gaim
causing it to become unresponsive and hang (CVE-2005-0472).

Gaim 1.1.4 is provided and fixes these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://gaim.sourceforge.net/security/index.php?id=10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://gaim.sourceforge.net/security/index.php?id=11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://gaim.sourceforge.net/security/index.php?id=12"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/06");
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
if (rpm_check(release:"MDK10.0", reference:"gaim-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"gaim-devel-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"gaim-perl-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"gaim-tcl-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gaim-remote0-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gaim-remote0-devel-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgaim-remote0-1.1.4-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgaim-remote0-devel-1.1.4-2.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"gaim-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-devel-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-gevolution-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-perl-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-tcl-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-devel-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-1.1.4-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-devel-1.1.4-2.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
