#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:024. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14123);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");
  script_xref(name:"MDKSA", value:"2004:024");

  script_name(english:"Mandrake Linux Security Advisory : ethereal (MDKSA-2004:024)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of serious issues have been discovered in versions of
Ethereal prior to 0.10.2. Stefan Esser discovered thirteen buffer
overflows in the NetFlow, IGAP, EIGRP, PGM, IrDA, BGP, ISUP, and TCAP
dissectors. Jonathan Heusser discovered that a carefully-crafted
RADIUS packet could cause Ethereal to crash. It was also found that a
zero-length Presentation protocol selector could make Ethereal crash.
Finally, a corrupt color filter file could cause a segmentation fault.
It is possible, through the exploitation of some of these
vulnerabilities, to cause Ethereal to crash or run arbitrary code by
injecting a malicious, malformed packet onto the wire, by convincing
someone to read a malformed packet trace file, or by creating a
malformed color filter file.

The updated packages bring Ethereal to version 0.10.3 which is not
vulnerable to these issues."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00013.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/30");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"ethereal-0.10.3-0.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"ethereal-0.10.3-0.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
