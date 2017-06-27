#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60284);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-4136");

  script_name(english:"Scientific Linux Security Update : conga on SL5.x i386/x86_64");
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
"A flaw was found in ricci during a code audit. A remote attacker who
is able to connect to ricci could cause ricci to temporarily refuse
additional connections, a denial of service (CVE-2007-4136).

Fixes in this updated package include :

  - The nodename is now set for manual fencing.

  - The node log no longer displays in random order.

  - A bug that prevented a node from responding when a
    cluster was deleted is now fixed.

  - A PAM configuration that incorrectly called the
    deprecated module pam_stack was removed.

  - A bug that prevented some quorum disk configurations
    from being accepted is now fixed.

  - Setting multicast addresses now works properly.

  - rpm -V on luci no longer fails.

  - The user interface rendering time for storage interface
    is now faster.

  - An error message that incorrectly appeared when
    rebooting nodes during cluster creation was removed.

  - Cluster snaps configuration (an unsupported feature) has
    been removed altogether to prevent user confusion.

  - A user permission bug resulting from a luci code error
    is now fixed.

  - luci and ricci init script return codes are now
    LSB-compliant.

  - VG creation on cluster nodes now defaults to
    'clustered'.

  - An SELinux AVC bug that prevented users from setting up
    shared storage on nodes is now fixed.

  - An access error that occurred when attempting to access
    a cluster node after its cluster was deleted is now
    fixed.

  - IP addresses can now be used to create clusters.

  - Attempting to configure a fence device no longer results
    in an AttributeError.

  - Attempting to create a new fence device to a valid
    cluster no longer results in a KeyError.

  - Several minor user interface validation errors have been
    fixed, such as enforcing cluster name length and fence
    port, etc.

  - A browser lock-up that could occur during storage
    configuration has been fixed.

  - Virtual service creation now works without error.

  - The fence_xvm tag is no longer misspelled in the
    cluster.conf file.

  - Luci failover forms are complete and working.

  - Rebooting a fresh cluster install no longer generates an
    error message.

  - A bug that prevented failed cluster services from being
    started is now fixed.

  - A bug that caused some cluster operations (e.g., node
    delete) to fail on clusters with mixed-cased cluster
    names is now fixed.

  - Global cluster resources can be reused when constructing
    cluster services.

Enhancements in this updated package include :

  - Users can now access Conga through Internet Explorer 6.

  - Dead nodes can now be evicted from a cluster.

  - Shared storage on new clusters is now enabled by
    default.

  - The fence user-interface flow is now simpler.

  - A port number is now shown in ricci error messages.

  - The kmod-gfs-xen kernel module is now installed when
    creating a cluster.

  - Cluster creation status is now shown visually.

  - User names are now sorted for display.

  - The fence_xvmd tag can now be added from the dom0
    cluster nodes.

  - The ampersand character (&amp;) can now be used in fence
    names.

  - All packaged files are now installed with proper owners
    and permissions.

  - New cluster node members are now properly initialized.

  - Storage operations can now be completed even if an LVM
    snapshot is present.

  - Users are now informed via dialog when nodes are
    rebooted as part of a cluster operation.

  - Failover domains are now properly listed for virtual
    services and traditional clustered services.

  - Luci can now create and distribute keys for fence_xvmd."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=1527
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7efb037c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"cluster-cim-0.10.0-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cluster-snmp-0.10.0-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"luci-0.10.0-6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"modcluster-0.10.0-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ricci-0.10.0-6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
