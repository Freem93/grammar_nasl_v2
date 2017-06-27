#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85204);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/13 13:44:24 $");

  script_cve_id("CVE-2015-1867");

  script_name(english:"Scientific Linux Security Update : pacemaker on SL6.x i386/x86_64");
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

This update also fixes the following bugs :

  - Due to a race condition, nodes that gracefully shut down
    occasionally had difficulty rejoining the cluster. As a
    consequence, nodes could come online and be shut down
    again immediately by the cluster. This bug has been
    fixed, and the 'shutdown' attribute is now cleared
    properly.

  - Prior to this update, the pacemaker utility caused an
    unexpected termination of the attrd daemon after a
    system update to Scientific Linux 6.6. The bug has been
    fixed so that attrd no longer crashes when pacemaker
    starts.

  - Previously, the access control list (ACL) of the
    pacemaker utility allowed a role assignment to the
    Cluster Information Base (CIB) with a read-only
    permission. With this update, ACL is enforced and can no
    longer be bypassed by the user without the write
    permission, thus fixing this bug.

  - Prior to this update, the ClusterMon (crm_mon) utility
    did not trigger an external agent script with the '-E'
    parameter to monitor the Cluster Information Base (CIB)
    when the pacemaker utility was used. A patch has been
    provided to fix this bug, and crm_mon now calls the
    agent script when the '-E' parameter is used."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=4316
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ad424cc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (rpm_check(release:"SL6", reference:"pacemaker-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cli-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cluster-libs-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-cts-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-debuginfo-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-doc-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-libs-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-libs-devel-1.1.12-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pacemaker-remote-1.1.12-8.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
