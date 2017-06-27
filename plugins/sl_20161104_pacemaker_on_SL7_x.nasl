#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95914);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2016-7797");

  script_name(english:"Scientific Linux Security Update : pacemaker on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
pacemaker (1.1.15).

Security Fix(es) :

  - It was found that the connection between a pacemaker
    cluster and a pacemaker_remote node could be shut down
    using a new unauthenticated connection. A remote
    attacker could use this flaw to cause a denial of
    service. (CVE-2016-7797)

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=11137
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42a35306"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.15-11.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
