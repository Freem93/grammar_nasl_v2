#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:086. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14335);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0689", "CVE-2004-0690", "CVE-2004-0721", "CVE-2004-0746");
  script_xref(name:"MDKSA", value:"2004:086");

  script_name(english:"Mandrake Linux Security Advisory : kdelibs/kdebase (MDKSA-2004:086)");
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
"A number of vulnerabilities were discovered in KDE that are corrected
with these update packages.

The integrity of symlinks used by KDE are not ensured and as a result
can be abused by local attackers to create or truncate arbitrary files
or to prevent KDE applications from functioning correctly
(CVE-2004-0689).

The DCOPServer creates temporary files in an insecure manner. These
temporary files are used for authentication-related purposes, so this
could potentially allow a local attacker to compromise the account of
any user running a KDE application (CVE-2004-0690). Note that only KDE
3.2.x is affected by this vulnerability.

The Konqueror web browser allows websites to load web pages into a
frame of any other frame-based web page that the user may have open.
This could potentially allow a malicious website to make Konqueror
insert its own frames into the page of an otherwise trusted website
(CVE-2004-0721).

The Konqueror web browser also allows websites to set cookies for
certain country-specific top-level domains. This can be done to make
Konqueror send the cookies to all other web sites operating under the
same domain, which can be abused to become part of a session fixation
attack. All country-specific secondary top-level domains that use more
than 2 characters in the secondary part of the domain name, and that
use a secondary part other than com, net, mil, org, gove, edu, or int
are affected (CVE-2004-0746)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040811-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040811-2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040811-3.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040820-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kcontrol-data");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
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
if (rpm_check(release:"MDK10.0", reference:"kdebase-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-common-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kate-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kcontrol-data-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdeprintfax-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdm-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kdm-config-file-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-kmenuedit-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-konsole-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-nsplugins-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdebase-progs-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kdelibs-common-3.2-36.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kate-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kate-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-kmenuedit-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-konsole-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-nsplugins-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdebase4-nsplugins-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-3.2-36.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64kdecore4-devel-3.2-36.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kate-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kate-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-kmenuedit-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-konsole-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-nsplugins-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdebase4-nsplugins-devel-3.2-79.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-3.2-36.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkdecore4-devel-3.2-36.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"kdebase-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-common-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-kate-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-kdeprintfax-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-kdm-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-kdm-config-file-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-konsole-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-nsplugins-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdebase-progs-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdelibs-common-3.1.3-35.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-kate-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-kate-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-konsole-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-nsplugins-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdebase4-nsplugins-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdecore4-3.1.3-35.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdecore4-devel-3.1.3-35.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-kate-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-kate-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-konsole-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-nsplugins-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdebase4-nsplugins-devel-3.1.3-79.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdecore4-3.1.3-35.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdecore4-devel-3.1.3-35.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
