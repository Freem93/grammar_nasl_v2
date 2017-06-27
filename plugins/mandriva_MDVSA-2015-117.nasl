#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:117. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82370);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-3421", "CVE-2014-3422", "CVE-2014-3423", "CVE-2014-3424");
  script_xref(name:"MDVSA", value:"2015:117");

  script_name(english:"Mandriva Linux Security Advisory : emacs (MDVSA-2015:117)");
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
"Updated emacs packages fix security vulnerabilities :

Steve Kemp discovered multiple temporary file handling issues in
Emacs. A local attacker could use these flaws to perform symbolic link
attacks against users running Emacs (CVE-2014-3421, CVE-2014-3422,
CVE-2014-3423, CVE-2014-3424)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0250.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-leim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"emacs-24.3-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"emacs-common-24.3-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"emacs-doc-24.3-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"emacs-el-24.3-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"emacs-leim-24.3-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"emacs-nox-24.3-7.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
