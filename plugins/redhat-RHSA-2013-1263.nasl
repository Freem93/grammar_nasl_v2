#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1263. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79289);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-0818");
  script_xref(name:"RHSA", value:"2013:1263");

  script_name(english:"RHEL 6 : Storage Server (RHSA-2013:1263)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat Storage Console packages that fix one security issue,
various bugs, and add enhancements are now available for Red Hat
Storage Server 2.1.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Storage Console (RHS-C) is a powerful and simple web based
Graphical User Interface for managing a Red Hat Storage 2.1
environment. This feature is provided as a Technology Preview, and is
currently not supported under Red Hat Storage subscription services.
Refer to the following for more information about Technology Previews:
https://access.redhat.com/support/offerings/techpreview/

It was found that RESTEasy was vulnerable to XML External Entity (XXE)
attacks. If a remote attacker who is able to access the Red Hat
Storage Console REST API submitted a request containing an external
XML entity to a RESTEasy endpoint, the entity would be resolved,
allowing the attacker to read files accessible to the user running the
application server. This flaw affected DOM (Document Object Model)
Document and JAXB (Java Architecture for XML Binding) input.
(CVE-2012-0818)

This update also fixes the following bugs :

* A new server could not be added to a cluster if the required
packages were not installed on the server. Now, the administrator can
add a server to a cluster which will automatically install the
required packages, if missing. (BZ#850431)

* Previously, the rhs-log-collector tool did not collect GlusterFS
related logs. (BZ#855271)

* Previously, it was not possible for rhsc-setup to complete
successfully on systems that have SELinux in disabled mode.
(BZ#841342)

* The 'Add Brick' button in the 'Add Bricks' pop up is now placed next
to the 'Brick Directory' field for a better UI experience. (BZ#863929)

* The UUID of the volume was not visible. Now, a new field is added to
the 'Summary' sub-tab of the 'Volumes' tab to display the UUIDs.
(BZ#887806)

* The web console was not accessible after a server reboot. The setup
mechanism has been modified to ensure the web console is accessible
after a server reboot. (BZ#838284)

This update also adds the following enhancements :

* Previously, to import an existing storage cluster into the Red Hat
Storage Console the hosts were added one by one. Now, a new feature
has been added that allows users to import an existing storage
cluster. The new Cluster Creation window has an option to import an
existing storage cluster. If IP_Address or the hostname and password
of one of the hosts of the cluster is entered, a list containing all
the hosts of the cluster is displayed and the same can be added to the
Console. The volumes which are part of the cluster also get imported.
(BZ#850438)

* The command line was required to enable a volume to use CIFS. Now,
you can enable or disable the export of a volume with the new 'CIFS'
checkbox in the 'Create Volume' window. (BZ#850452)

* The new Red Hat Support plug-in for Red Hat Storage is a Technology
Preview feature that offers seamless, integrated access to the Red Hat
subscription services from the Red Hat Customer Portal. Subscribers
who install this plug-in can access these features :

  - Create, manage, and update the Red Hat support cases. -
    Conveniently access exclusive Red Hat knowledge and
    solutions. - Search error codes, messages, etc. and view
    related knowledge from the Red Hat Customer Portal.
    (BZ#999245)

* A new 'Event ID' column is added to the 'Events' table in the
'Advanced View' of 'Events' tab which allows users to see the ID of
each event in the 'Events' tab. (BZ#889942)

* A new feature is added to manage and monitor the hooks on the
Console. It also reports changes in the hooks and checks for new hook
scripts by polling at regular intervals. (BZ#850483)

* A new 'Optimize for Virt Store' option is added to optimize a volume
to use it as a virt store. The system sets the 'virt' group option on
the volume and also the following two volume options :

  - storage.owner-uid=36 - storage.owner-gid=36

This option is available during volume creation and also for existing
volumes. (BZ#891493, BZ#891491)

All users of Red Hat Storage Server 2.1 are advised to upgrade to
these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/offerings/techpreview/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1263.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:otopi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:otopi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:otopi-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:otopi-repolib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-host-deploy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-host-deploy-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-host-deploy-repolib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kitchen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-access-plugin-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-log-collector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhsc-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1263";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"redhat-storage-server"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Storage Server");

  if (rpm_check(release:"RHEL6", reference:"otopi-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"otopi-devel-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"otopi-java-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"otopi-repolib-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ovirt-host-deploy-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ovirt-host-deploy-java-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ovirt-host-deploy-repolib-1.1.0-1.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-daemon-1.5.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-kitchen-1.1.1-2.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-lockfile-0.8-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-ply-3.3-7.el6ev")) flag++;
  if (rpm_check(release:"RHEL6", reference:"redhat-access-plugin-storage-2.1.0-0.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-backend-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-cli-2.1.0.0-0.bb3a.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-dbscripts-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-log-collector-2.1-0.1.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-restapi-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-sdk-2.1.0.0-0.bb3a.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-setup-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-tools-2.1.0-0.bb10.el6rhs")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhsc-webadmin-portal-2.1.0-0.bb10.el6rhs")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "otopi / otopi-devel / otopi-java / otopi-repolib / etc");
  }
}
