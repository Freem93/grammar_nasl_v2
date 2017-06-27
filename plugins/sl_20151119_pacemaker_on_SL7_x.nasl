#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87568);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-1867");

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
"A flaw was found in the way pacemaker, a cluster resource manager,
evaluated added nodes in certain situations. A user with read-only
access could potentially assign any other existing roles to themselves
and then add privileges to other users as well. (CVE-2015-1867)

The pacemaker packages have been upgraded to upstream version 1.1.13,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bugs :

  - When a Pacemaker cluster included an Apache resource,
    and Apache's mod_systemd module was enabled, systemd
    rejected notifications sent by Apache. As a consequence,
    a large number of errors in the following format
    appeared in the system log :

Got notification message from PID XXXX, but reception only permitted
for PID YYYY

With this update, the lrmd daemon now unsets the 'NOTIFY_SOCKET'
variable in the described circumstances, and these error messages are
no longer logged.

  - Previously, specifying a remote guest node as a part of
    a group resource in a Pacemaker cluster caused the node
    to stop working. This update adds support for remote
    guests in Pacemaker group resources, and the described
    problem no longer occurs.

  - When a resource in a Pacemaker cluster failed to start,
    Pacemaker updated the resource's last failure time and
    incremented its fail count even if the 'on-fail=ignore'
    option was used. This in some cases caused unintended
    resource migrations when a resource start failure
    occurred. Now, Pacemaker does not update the fail count
    when 'on-fail=ignore' is used. As a result, the failure
    is displayed in the cluster status output, but is
    properly ignored and thus does not cause resource
    migration.

  - Previously, Pacemaker supported semicolon characters
    (';') as delimiters when parsing the pcmk_host_map
    string, but not when parsing the pcmk_host_list string.
    To ensure consistent user experience, semicolons are now
    supported as delimiters for parsing pcmk_host_list, as
    well.

In addition, this update adds the following enhancements :

  - If a Pacemaker location constraint has the
    'resource-discovery=never' option, Pacemaker now does
    not attempt to determine whether a specified service is
    running on the specified node. In addition, if multiple
    location constraints for a given resource specify
    'resource- discovery=exclusive', then Pacemaker attempts
    resource discovery only on the nodes specified in those
    constraints. This allows Pacemaker to skip resource
    discovery on nodes where attempting the operation would
    lead to error or other undesirable behavior.

  - The procedure of configuring fencing for redundant power
    supplies has been simplified in order to prevent
    multiple nodes accessing cluster resources at the same
    time and thus causing data corruption. For further
    information, see the 'Fencing: Configuring STONITH'
    chapter of the High Availability Add-On Reference
    manual.

  - The output of the 'crm_mon' and 'pcs_status' commands
    has been modified to be clearer and more concise, and
    thus easier to read when reporting the status of a
    Pacemaker cluster with a large number of remote nodes
    and cloned resources."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=4523
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bae9522e"
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.13-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.13-10.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
