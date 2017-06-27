#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:150. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15981);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-0721", "CVE-2004-1158", "CVE-2004-1171");
  script_xref(name:"MDKSA", value:"2004:150");

  script_name(english:"Mandrake Linux Security Advisory : kdelibs (MDKSA-2004:150)");
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
"Daniel Fabian discovered a potential privacy issue in KDE. When
creating a link to a remote file from various applications, including
Konqueror, the resulting URL may contain the authentication
credentials used to access that remote resource. This includes, but is
not limited to, browsing SMB (Samba) shares. Upon further
investigation, it was found that the SMB protocol handler also
unnecessarily exposed authentication credentials (CVE-2004-1171).

Another vulnerability was discovered where a malicious website could
abuse Konqueror to load its own content into a window or tab that was
opened by a trusted website, or it could trick a trusted website into
loading content into an existing window or tab. This could lead to the
user being confused as to the origin of a particular webpage and could
have the user unknowingly send confidential information intended for a
trusted site to the malicious site (CVE-2004-1158).

The updated packages contain a patch from the KDE team to solve this
issue.

Additionally, the kdelibs and kdebase packages for Mandrakelinux 10.1
contain numerous bugfixes. New qt3 packages are being provided for
Mandrakelinux 10.0 that are required to build the kdebase package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040811-3.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20041209-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kcontrol-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kcontrol-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdeprintfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm-config-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-nsplugins-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-nsplugins-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mandrakelinux-kde-config-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-example");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/15");
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
if (rpm_check(release:"MDK10.0", reference:"kdebase-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-common-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kate-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kcontrol-data-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdeprintfax-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdm-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdm-config-file-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kmenuedit-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-konsole-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-nsplugins-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-progs-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdelibs-common-3.2-36.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kate-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kate-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kmenuedit-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-konsole-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-nsplugins-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-nsplugins-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-3.2-36.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-devel-3.2-36.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-devel-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-mysql-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-odbc-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-psql-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kate-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kate-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kmenuedit-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-konsole-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-nsplugins-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-nsplugins-devel-3.2-79.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-3.2-36.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-devel-3.2-36.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-devel-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-mysql-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-odbc-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-psql-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"mandrakelinux-kde-config-file-10.1-6.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mandrakelinux-kde-config-file-10.1-6.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"qt3-common-3.2.3-19.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"qt3-example-3.2.3-19.6.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"kdebase-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-common-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kate-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kcontrol-data-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kcontrol-nsplugins-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdeprintfax-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdm-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdm-config-file-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kmenuedit-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-konsole-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-nsplugins-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-progs-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdelibs-common-3.2.3-98.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-devel-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kate-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kate-devel-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kmenuedit-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-konsole-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdecore4-3.2.3-98.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdecore4-devel-3.2.3-98.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-devel-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kate-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kate-devel-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kmenuedit-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-konsole-3.2.3-134.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdecore4-3.2.3-98.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdecore4-devel-3.2.3-98.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
