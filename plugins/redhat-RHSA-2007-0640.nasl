#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0640. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63842);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2007-4136");
  script_osvdb_id(39853);
  script_xref(name:"RHSA", value:"2007:0640");

  script_name(english:"RHEL 5 : conga (RHSA-2007:0640)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that correct a security flaw and provide bug
fixes and add enhancements are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Conga package is a web-based administration tool for remote
cluster and storage management.

A flaw was found in ricci during a code audit. A remote attacker who
is able to connect to ricci could cause ricci to temporarily refuse
additional connections, a denial of service (CVE-2007-4136).

Fixes in this updated package include :

* The nodename is now set for manual fencing.

* The node log no longer displays in random order.

* A bug that prevented a node from responding when a cluster was
deleted is now fixed.

* A PAM configuration that incorrectly called the deprecated module
pam_stack was removed.

* A bug that prevented some quorum disk configurations from being
accepted is now fixed.

* Setting multicast addresses now works properly.

* rpm -V on luci no longer fails.

* The user interface rendering time for storage interface is now
faster.

* An error message that incorrectly appeared when rebooting nodes
during cluster creation was removed.

* Cluster snaps configuration (an unsupported feature) has been
removed altogether to prevent user confusion.

* A user permission bug resulting from a luci code error is now fixed.

* luci and ricci init script return codes are now LSB-compliant.

* VG creation on cluster nodes now defaults to 'clustered'.

* An SELinux AVC bug that prevented users from setting up shared
storage on nodes is now fixed.

* An access error that occurred when attempting to access a cluster
node after its cluster was deleted is now fixed.

* IP addresses can now be used to create clusters.

* Attempting to configure a fence device no longer results in an
AttributeError.

* Attempting to create a new fence device to a valid cluster no longer
results in a KeyError.

* Several minor user interface validation errors have been fixed, such
as enforcing cluster name length and fence port, etc.

* A browser lock-up that could occur during storage configuration has
been fixed.

* Virtual service creation now works without error.

* The fence_xvm tag is no longer misspelled in the cluster.conf file.

* Luci failover forms are complete and working. * Rebooting a fresh
cluster install no longer generates an error message.

* A bug that prevented failed cluster services from being started is
now fixed.

* A bug that caused some cluster operations (e.g., node delete) to
fail on clusters with mixed-cased cluster names is now fixed.

* Global cluster resources can be reused when constructing cluster
services.

Enhancements in this updated package include :

* Users can now access Conga through Internet Explorer 6.

* Dead nodes can now be evicted from a cluster.

* Shared storage on new clusters is now enabled by default.

* The fence user-interface flow is now simpler.

* A port number is now shown in ricci error messages.

* The kmod-gfs-xen kernel module is now installed when creating a
cluster.

* Cluster creation status is now shown visually.

* User names are now sorted for display.

* The fence_xvmd tag can now be added from the dom0 cluster nodes.

* The ampersand character (&) can now be used in fence names.

* All packaged files are now installed with proper owners and
permissions.

* New cluster node members are now properly initialized.

* Storage operations can now be completed even if an LVM snapshot is
present.

* Users are now informed via dialog when nodes are rebooted as part of
a cluster operation.

* Failover domains are now properly listed for virtual services and
traditional clustered services.

* Luci can now create and distribute keys for fence_xvmd.

All Conga users are advised to upgrade to this update, which applies
these fixes and enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0640.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected luci and / or ricci packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"luci-0.10.0-6.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"luci-0.10.0-6.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ricci-0.10.0-6.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ricci-0.10.0-6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
