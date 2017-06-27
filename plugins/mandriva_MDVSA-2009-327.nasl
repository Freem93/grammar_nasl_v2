#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:327. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(43076);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2008-6680", "CVE-2009-1241", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");
  script_bugtraq_id(34344);
  script_xref(name:"MDVSA", value:"2009:327");

  script_name(english:"Mandriva Linux Security Advisory : clamav (MDVSA-2009:327)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in clamav :

Unspecified vulnerability in ClamAV before 0.95 allows remote
attackers to bypass detection of malware via a modified RAR archive
(CVE-2009-1241).

libclamav/pe.c in ClamAV before 0.95 allows remote attackers to cause
a denial of service (crash) via a crafted EXE file that triggers a
divide-by-zero error (CVE-2008-6680).

libclamav/untar.c in ClamAV before 0.95 allows remote attackers to
cause a denial of service (infinite loop) via a crafted file that
causes (1) clamd and (2) clamscan to hang (CVE-2009-1270).

The CLI_ISCONTAINED macro in libclamav/others.h in ClamAV before
0.95.1 allows remote attackers to cause a denial of service
(application crash) via a malformed file with UPack encoding
(CVE-2009-1371).

Stack-based buffer overflow in the cli_url_canon function in
libclamav/phishcheck.c in ClamAV before 0.95.1 allows remote attackers
to cause a denial of service (application crash) and possibly execute
arbitrary code via a crafted URL (CVE-2009-1372).

Important notice about this upgrade: clamav-0.95+ bundles support for
RAR v3 in libclamav which is a license violation as the RAR v3 license
and the GPL license is not compatible. As a consequence to this
Mandriva has been forced to remove the RAR v3 code.

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

This update provides clamav 0.95.2, which is not vulnerable to these
issues. Additionally klamav-0.46 is being provided that has support
for clamav-0.95+."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:klamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"clamav-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamav-db-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamav-milter-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamd-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"klamav-0.46-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64clamav-devel-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64clamav6-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libclamav-devel-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libclamav6-0.95.2-0.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
