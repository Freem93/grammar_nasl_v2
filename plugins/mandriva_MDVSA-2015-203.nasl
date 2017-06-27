#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:203. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82738);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2015-0250");
  script_xref(name:"MDVSA", value:"2015:203");

  script_name(english:"Mandriva Linux Security Advisory : batik (MDVSA-2015:203)");
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
"Updated batik packages fix security vulnerability :

Nicolas Gregoire and Kevin Schaller discovered that Batik would load
XML external entities by default. If a user or automated system were
tricked into opening a specially crafted SVG file, an attacker could
possibly obtain access to arbitrary files or cause resource
consumption (CVE-2015-0250)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0138.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-rasterizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-slideshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-squiggle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-svgpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:batik-ttf2svg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
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
if (rpm_check(release:"MDK-MBS1", reference:"batik-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-demo-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-javadoc-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-rasterizer-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-slideshow-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-squiggle-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-svgpp-1.8-0.1.svn1230816.4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"batik-ttf2svg-1.8-0.1.svn1230816.4.1.mbs1")) flag++;

if (rpm_check(release:"MDK-MBS2", reference:"batik-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-demo-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-javadoc-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-rasterizer-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-slideshow-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-squiggle-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-svgpp-1.8-0.1.svn1230816.11.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"batik-ttf2svg-1.8-0.1.svn1230816.11.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
