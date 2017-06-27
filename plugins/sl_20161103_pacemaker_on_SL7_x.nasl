#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95852);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-7035");

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
"Security Fix(es) :

  - An authorization flaw was found in Pacemaker, where it
    did not properly guard its IPC interface. An attacker
    with an unprivileged account on a Pacemaker node could
    use this flaw to, for example, force the Local Resource
    Manager daemon to execute a script as root and thereby
    gain root access on the machine. (CVE-2016-7035)

Bug Fix(es) :

  - The version of Pacemaker in Scientific Linux 7.3
    incorporated an increase in the version number of the
    remote node protocol. Consequently, cluster nodes
    running Pacemaker in Scientific Linux 7.3 and remote
    nodes running earlier versions of Scientific Linux were
    not able to communicate with each other unless special
    precautions were taken. This update preserves the
    rolling upgrade capability."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=1035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4afea3c6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.15-11.el7_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
