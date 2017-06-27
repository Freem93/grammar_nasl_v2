#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60840);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936");

  script_name(english:"Scientific Linux Security Update : openoffice.org on SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer truncation error, leading to a heap-based buffer overflow,
was found in the way the OpenOffice.org Impress presentation
application sanitized a file's dictionary property items. An attacker
could use this flaw to create a specially crafted Microsoft Office
PowerPoint file that, when opened, would cause OpenOffice.org Impress
to crash or, possibly, execute arbitrary code with the privileges of
the user running OpenOffice.org Impress. (CVE-2010-2935)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way OpenOffice.org Impress processed polygons in input
documents. An attacker could use this flaw to create a specially
crafted Microsoft Office PowerPoint file that, when opened, would
cause OpenOffice.org Impress to crash or, possibly, execute arbitrary
code with the privileges of the user running OpenOffice.org Impress.
(CVE-2010-2936)

All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=2764
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9db4f813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openoffice.org, openoffice.org-i18n and / or
openoffice.org-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL3", reference:"openoffice.org-1.1.2-48.2.0.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"openoffice.org-i18n-1.1.2-48.2.0.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"openoffice.org-libs-1.1.2-48.2.0.EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
