#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97037);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/07 14:52:10 $");

  script_cve_id("CVE-2016-9577", "CVE-2016-9578");

  script_name(english:"Scientific Linux Security Update : spice on SL7.x x86_64");
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
"Security Fix(es) :

  - A vulnerability was discovered in spice in the server's
    protocol handling. An authenticated attacker could send
    crafted messages to the spice server causing a heap
    overflow leading to a crash or possible code execution.
    (CVE-2016-9577)

  - A vulnerability was discovered in spice in the server's
    protocol handling. An attacker able to connect to the
    spice server could send crafted messages which would
    cause the process to crash. (CVE-2016-9578)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=995
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0f2ff9c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected spice-debuginfo, spice-server and / or
spice-server-devel packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-debuginfo-0.12.4-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-server-0.12.4-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-server-devel-0.12.4-20.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
