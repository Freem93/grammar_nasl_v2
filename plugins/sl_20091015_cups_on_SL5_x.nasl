#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60677);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2009-3608", "CVE-2009-3609");

  script_name(english:"Scientific Linux Security Update : cups on SL5.x i386/x86_64");
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
"Two integer overflow flaws were found in the CUPS 'pdftops' filter. An
attacker could create a malicious PDF file that would cause 'pdftops'
to crash or, potentially, execute arbitrary code as the 'lp' user if
the file was printed. (CVE-2009-3608, CVE-2009-3609)

After installing the update, the cupsd daemon will be restarted
automatically.

Note: Some older versions of SL 5 needed a newer version of rpm for
this update. The SL 5.4 version of rpm and popt is included with this
update.

Note: This update is already in SL 5.4"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=1468
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a119d919"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"cups-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"popt-1.10.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-4.4.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-apidocs-4.4.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-build-4.4.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-devel-4.4.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-libs-4.4.2.3-18.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-python-4.4.2.3-18.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
