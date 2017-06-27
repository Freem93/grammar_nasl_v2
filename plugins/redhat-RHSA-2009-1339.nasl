#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1339. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63893);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2008-6552");
  script_xref(name:"RHSA", value:"2009:1339");

  script_name(english:"RHEL 5 : rgmanager (RHSA-2009:1339)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rgmanager package that fixes multiple security issues,
various bugs, and adds enhancements is now available for Red Hat
Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The rgmanager package contains the Red Hat Resource Group Manager,
which provides high availability for critical server applications in
the event of system downtime.

Multiple insecure temporary file use flaws were discovered in
rgmanager and various resource scripts run by rgmanager. A local
attacker could use these flaws to overwrite an arbitrary file writable
by the rgmanager process (i.e. user root) with the output of rgmanager
or a resource agent via a symbolic link attack. (CVE-2008-6552)

This update also fixes the following bugs :

* clulog now accepts '-' as the first character in messages.

* if expire_time is 0, max_restarts is no longer ignored.

* the SAP resource agents included in the rgmanager package shipped
with Red Hat Enterprise Linux 5.3 were outdated. This update includes
the most recent SAP resource agents and, consequently, improves SAP
failover support.

* empty PID files no longer cause resource start failures.

* recovery policy of type 'restart' now works properly when using a
resource based on ra-skelet.sh.

* samba.sh has been updated to kill the PID listed in the proper PID
file.

* handling of the '-F' option has been improved to fix issues causing
rgmanager to crash if no members of a restricted failover domain were
online.

* the number of simultaneous status checks can now be limited to
prevent load spikes.

* forking and cloning during status checks has been optimized to
reduce load spikes.

* rg_test no longer hangs when run with large cluster configuration
files.

* when rgmanager is used with a restricted failover domain it will no
longer occasionally segfault when some nodes are offline during a
failover event.

* virtual machine guests no longer restart after a cluster.conf
update.

* nfsclient.sh no longer leaves temporary files after running.

* extra checks from the Oracle agents have been removed.

* vm.sh now uses libvirt.

* users can now define an explicit service processing order when
central_processing is enabled.

* virtual machine guests can no longer start on 2 nodes at the same
time.

* in some cases a successfully migrated virtual machine guest could
restart when the cluster.conf file was updated.

* incorrect reporting of a service being started when it was not
started has been addressed.

As well, this update adds the following enhancements :

* a startup_wait option has been added to the MySQL resource agent.

* services can now be prioritized.

* rgmanager now checks to see if it has been killed by the OOM killer
and if so, reboots the node.

Users of rgmanager are advised to upgrade to this updated package,
which resolves these issues and adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-6552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1339.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rgmanager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
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
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rgmanager-2.0.52-1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rgmanager-2.0.52-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
