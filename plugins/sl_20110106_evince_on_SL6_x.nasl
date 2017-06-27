#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60930);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");

  script_name(english:"Scientific Linux Security Update : evince on SL6.x i386/x86_64");
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
"An array index error was found in the DeVice Independent (DVI)
renderer's PK and VF font file parsers. A DVI file that references a
specially crafted font file could, when opened, cause Evince to crash
or, potentially, execute arbitrary code with the privileges of the
user running Evince. (CVE-2010-2640, CVE-2010-2641)

A heap-based buffer overflow flaw was found in the DVI renderer's AFM
font file parser. A DVI file that references a specially crafted font
file could, when opened, cause Evince to crash or, potentially,
execute arbitrary code with the privileges of the user running Evince.
(CVE-2010-2642)

An integer overflow flaw was found in the DVI renderer's TFM font file
parser. A DVI file that references a specially crafted font file
could, when opened, cause Evince to crash or, potentially, execute
arbitrary code with the privileges of the user running Evince.
(CVE-2010-2643)

Note: The above issues are not exploitable unless an attacker can
trick the user into installing a malicious font file."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=4672
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac2eda7d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
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
if (rpm_check(release:"SL6", reference:"evince-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"evince-devel-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"evince-dvi-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"evince-libs-2.28.2-14.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
