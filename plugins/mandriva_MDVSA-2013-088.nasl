#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:088. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66100);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:40 $");

  script_cve_id("CVE-2013-0200");
  script_bugtraq_id(58079);
  script_xref(name:"MDVSA", value:"2013:088");
  script_xref(name:"MGASA", value:"2013-0072");

  script_name(english:"Mandriva Linux Security Advisory : hplip (MDVSA-2013:088)");
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
"This hplip update addresses the folloving issues :

Print/Fax queues can now be analyzed by running hp-diagnose-queues

fixes some issues and duplex scanning support with newer AIO devices

fixes Wireless configuration using hp-wificonfig command for HP
Deskjet 3000 J310 series and HP Deskjet 3050 J610 series

fixes the blurry printing issue on HP LaserJet CP1025 and CP1025nw

Full changelog is available upstream:
http://hplipopensource.com/hplip-web/release_notes.html Also note
there were several issues fixed upstream.

Some HP printers / multi-function devices require plugins additionally
to hplip to function correctly. This update makes the installation of
such plugins possible again.

Several temporary file handling flaws were found in HPLIP. A local
attacker could use these flaws to perform a symbolic link attack,
overwriting arbitrary files accessible to a process using HPLIP
(CVE-2013-0200)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mageia.org/en/Support/Advisories/MGAA-2012-0121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mageia.org/en/Support/Advisories/MGAA-2012-0220"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-hpijs-ppds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hplip-model-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hpip0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hpip0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sane-hpaio1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-doc-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-hpijs-ppds-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"hplip-model-data-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64hpip0-devel-3.12.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64sane-hpaio1-3.12.4-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
