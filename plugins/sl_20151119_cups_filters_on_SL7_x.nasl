#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87553);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-3258", "CVE-2015-3279");

  script_name(english:"Scientific Linux Security Update : cups-filters on SL7.x x86_64");
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
"A heap-based buffer overflow flaw and an integer overflow flaw leading
to a heap-based buffer overflow were discovered in the way the
texttopdf utility of cups-filter processed print jobs with a specially
crafted line size. An attacker able to submit print jobs could use
these flaws to crash texttopdf or, possibly, execute arbitrary code
with the privileges of the 'lp' user. (CVE-2015-3258, CVE-2015-3279)

Notably, this update also fixes the following bug :

  - Previously, when polling CUPS printers from a CUPS
    server, when a printer name contained an underscore (_),
    the client displayed the name containing a hyphen (-)
    instead. This made the print queue unavailable. With
    this update, CUPS allows the underscore character in
    printer names, and printers appear as shown on the CUPS
    server as expected.

In addition, this update adds the following enhancement :

  - Now, the information from local and remote CUPS servers
    is cached during each poll, and the CUPS server load is
    reduced."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=6636
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e9e6380"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-filters-1.0.35-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-filters-debuginfo-1.0.35-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-filters-devel-1.0.35-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cups-filters-libs-1.0.35-21.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
