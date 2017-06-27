#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1580. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64007);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2010-3389");
  script_bugtraq_id(44359);
  script_osvdb_id(68808);
  script_xref(name:"RHSA", value:"2011:1580");

  script_name(english:"RHEL 6 : resource-agents (RHSA-2011:1580)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated resource-agents package that fixes one security issue,
several bugs, and adds multiple enhancements is now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The resource-agents package contains a set of scripts to interface
with several services to operate in a High Availability environment
for both Pacemaker and rgmanager service managers.

It was discovered that certain resource agent scripts set the
LD_LIBRARY_PATH environment variable to an insecure value containing
empty path elements. A local user able to trick a user running those
scripts to run them while working from an attacker-writable directory
could use this flaw to escalate their privileges via a specially
crafted dynamic library. (CVE-2010-3389)

Red Hat would like to thank Raphael Geissert for reporting this issue.

This update also fixes the following bugs :

* When using the Sybase database and the ASEHAagent resource in the
cluster.conf file, it was not possible to run more than one ASEHAagent
per Sybase installation. Consequently, a second ASEHA (Sybase Adaptive
Server Enterprise (ASE) with the High Availability Option) agent could
not be run. This bug has been fixed and it is now possible to use two
ASEHA agents using the same Sybase installation. (BZ#711852)

* The s/lang scripts, which implement internal functionality for the
rgmanager package, while the central_processing option is in use, were
included in the wrong package. Now, the rgmanager and resource-agents
packages require each other for installation to prevent problems when
they are used separately. (BZ#693518)

* Previously, the oracledb.sh script was using the 'shutdown abort'
command as the first attempt to shut down a database. With this
update, oracledb.sh first attempts a graceful shutdown via the
'shutdown immediate' command before forcing the shutdown. (BZ#689801)

* Previously, when setting up a service on a cluster with a shared IP
resource and an Apache resource, the generated httpd.conf file
contained a bug in the line describing the shared IP address (the
'Listen' line). Now, the Apache resource agent generates the 'Listen'
line properly. (BZ#667217)

* If a high-availability (HA) cluster service was defined with an
Apache resource and was named with two words, such as 'kickstart
httpd', the service never started because it could not find a
directory with the space character in its name escaped. Now, Apache
resources work properly if a name contains a space as described above.
(BZ#667222)

* When inheritance was used in the cluster.conf file, a bug in the
/usr/share/cluster/nfsclient.sh file prevented it from monitoring NFS
exports properly. Consequently, monitoring of NFS exports to NFS
clients resulted in an endless loop. This bug has been fixed and the
monitoring now works as expected. (BZ#691814)

* Previously, the postgres-8 resource agent did not detect when a
PostgreSQL server failed to start. This bug has been fixed and
postgres-8 now works as expected in the described scenario.
(BZ#694816)

* When using the Pacemaker resource manager, the fs.sh resource agent
reported an error condition, if called with the 'monitor' parameter
and the referenced device did not exist. Consequently, the error
condition prevented the resource from being started. Now, fs.sh
returns the proper response code in the described scenario, thus
fixing this bug. (BZ#709400)

* Previously, numerous RGManager resource agents returned incorrect
response codes when coupled with the Pacemaker resource manager. Now,
the agents have been updated to work with Pacemaker properly.
(BZ#727643)

This update also adds the following enhancement :

* With this update, when the network is removed from a node using the
netfs.sh resource agent, it now recovers faster than previously.
(BZ#678497)

As well, this update upgrades the resource-agents package to upstream
version 3.9.2, which provides a number of bug fixes and enhancements
over the previous version. (BZ#707127)

All users of resource-agents are advised to upgrade to this updated
package, which corrects these issues and adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1580.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected resource-agents and / or resource-agents-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resource-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:1580";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"resource-agents-3.9.2-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"resource-agents-3.9.2-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"resource-agents-debuginfo-3.9.2-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"resource-agents-debuginfo-3.9.2-7.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "resource-agents / resource-agents-debuginfo");
  }
}
