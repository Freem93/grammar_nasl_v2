#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87569);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-3225");

  script_name(english:"Scientific Linux Security Update : pcs on SL7.x x86_64");
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
"A flaw was found in a way Rack processed parameters of incoming
requests. An attacker could use this flaw to send a crafted request
that would cause an application using Rack to crash. (CVE-2015-3225)

The pcs package has been upgraded to upstream version 0.9.143, which
provides a number of bug fixes and enhancements over the previous
version.

  - The pcs resource move and pcs resource ban commands now
    display a warning message to clarify the commands'
    behavior

  - New command to move a Pacemaker resource to its
    preferred node

This update also fixes the following bugs :

  - Before this update, a bug caused location, ordering, and
    colocation constraints related to a resource group to be
    removed when removing any resource from that group. This
    bug has been fixed, and the constraints are now
    preserved until the group has no resources left, and is
    removed.

  - Previously, when a user disabled a resource clone or
    multi-state resource, and then later enabled a primitive
    resource within it, the clone or multi-state resource
    remained disabled. With this update, enabling a resource
    within a disabled clone or multi-state resource enables
    it.

  - When the web UI displayed a list of resource attributes,
    a bug caused the list to be truncated at the first '='
    character. This update fixes the bug and now the web UI
    displays lists of resource attributes correctly.

  - The documentation for the 'pcs stonith confirm' command
    was not clear. This could lead to incorrect usage of the
    command, which could in turn cause data corruption. With
    this update, the documentation has been improved and the
    'pcs stonith confirm' command is now more clearly
    explained.

  - Previously, if there were any unauthenticated nodes,
    creating a new cluster, adding a node to an existing
    cluster, or adding a cluster to the web UI failed with
    the message 'Node is not authenticated'. With this
    update, when the web UI detects a problem with
    authentication, the web UI displays a dialog to
    authenticate nodes as necessary.

  - Previously, the web UI displayed only primitive
    resources. Thus there was no way to set attributes,
    constraints and other properties separately for a parent
    resource and a child resource. This has now been fixed,
    and resources are displayed in a tree structure, meaning
    all resource elements can be viewed and edited
    independently.

In addition, this update adds the following enhancements :

  - A dashboard has been added which shows the status of
    clusters in the web UI. Previously, it was not possible
    to view all important information about clusters in one
    place. Now, a dashboard showing the status of clusters
    has been added to the main page of the web UI.

  - With this update, the pcsd daemon automatically
    synchronizes pcsd configuration across a cluster. This
    enables the web UI to be run from any node, allowing
    management even if any particular node is down.

  - The web UI can now be used to set permissions for users
    and groups on a cluster. This allows users and groups to
    have their access restricted to certain operations on
    certain clusters."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=14243
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?482af0a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcs and / or pcs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-0.9.143-15.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-debuginfo-0.9.143-15.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
