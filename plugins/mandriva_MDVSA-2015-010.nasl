#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:010. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(80429);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/04 14:37:26 $");

  script_cve_id("CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9621");
  script_bugtraq_id(71692, 71700);
  script_xref(name:"MDVSA", value:"2015:010");

  script_name(english:"Mandriva Linux Security Advisory : file (MDVSA-2015:010)");
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
"Updated file packages fix security vulnerabilities :

Thomas Jarosch of Intra2net AG reported that using the file command on
a specially crafted ELF binary could lead to a denial of service due
to uncontrolled resource consumption (CVE-2014-8116).

Thomas Jarosch of Intra2net AG reported that using the file command on
a specially crafted ELF binary could lead to a denial of service due
to uncontrolled recursion (CVE-2014-8117).

The ELF parser in file 5.08 through 5.21 allows remote attackers to
cause a denial of service via a large number of notes (CVE-2014-9620).

The ELF parser in file 5.16 through 5.21 allows remote attackers to
cause a denial of service via a long string (CVE-2014-9621).

The updated file packages has been upgraded to the latest 5.22 version
which is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0537.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magic-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"file-5.22-1.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64magic-devel-5.22-1.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64magic-static-devel-5.22-1.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64magic1-5.22-1.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"python-magic-5.22-1.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
