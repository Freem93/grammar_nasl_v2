#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87565);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-3248");

  script_name(english:"Scientific Linux Security Update : openhpi on SL7.x x86_64");
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
"It was found that the '/var/lib/openhpi' directory provided by OpenHPI
used world-writeable and world-readable permissions. A local user
could use this flaw to view, modify, and delete OpenHPI-related data,
or even fill up the storage device hosting the /var/lib directory.
(CVE-2015-3248)

The openhpi packages have been upgraded to upstream version 3.4.0,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bug :

  - Network timeouts were handled incorrectly in the
    openhpid daemon. As a consequence, network connections
    could fail when external plug-ins were used. With this
    update, handling of network socket timeouts has been
    improved in openhpid, and the described problem no
    longer occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=8750
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9584ba57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openhpi-3.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openhpi-debuginfo-3.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openhpi-devel-3.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openhpi-libs-3.4.0-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
