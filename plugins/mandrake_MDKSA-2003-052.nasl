#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:052. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14036);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2003-0209");
  script_xref(name:"MDKSA", value:"2003:052");

  script_name(english:"Mandrake Linux Security Advisory : snort (MDKSA-2003:052)");
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
"An integer overflow was discovered in the Snort stream4 preprocessor
by the Sourcefire Vulnerability Research Team. This preprocessor
(spp_stream4) incorrectly calculates segment size parameters during
stream reassembly for certainm sequence number ranges. This can lead
to an integer overflow that can in turn lead to a heap overflow that
can be exploited to perform a denial of service (DoS) or even remote
command excution on the host running Snort.

Disabling the stream4 preprocessor will make Snort invulnerable to
this attack, and the flaw has been fixed upstream in Snort version
2.0. Snort versions 1.8 through 1.9.1 are vulnerable."
  );
  # http://www.snort.org/advisories/snort-2003-04-16-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83850a84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-bloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-mysql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-plain+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-postgresql+flexresp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:snort-snmp+flexresp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/28");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-bloat-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-mysql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-mysql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-plain+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-postgresql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-snmp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"snort-snmp+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-bloat-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-mysql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-mysql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-plain+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-postgresql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-snmp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"snort-snmp+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-bloat-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-mysql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-mysql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-plain+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-postgresql-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-snmp-2.0.0-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"snort-snmp+flexresp-2.0.0-2.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
