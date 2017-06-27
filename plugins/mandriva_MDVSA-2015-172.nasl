#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:172. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82448);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/31 13:56:07 $");

  script_cve_id("CVE-2014-9492");
  script_xref(name:"MDVSA", value:"2015:172");

  script_name(english:"Mandriva Linux Security Advisory : firebird (MDVSA-2015:172)");
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
"Updated firebird packages fix a remote denial of service 
vulnerability :

These update fix the recently discovered security vulnerability
(CORE-4630) that may be used for a remote DoS attack performed by
unauthorized users (CVE-2014-9492)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0523.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-server-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-server-superserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-superclassic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-superserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-utils-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firebird-utils-superserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64fbclient2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64fbembed2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-classic-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-devel-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-server-classic-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-server-common-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-server-superserver-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-superclassic-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-superserver-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-utils-classic-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-utils-common-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"firebird-utils-superserver-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64fbclient2-2.5.2.26540-4.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64fbembed2-2.5.2.26540-4.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
