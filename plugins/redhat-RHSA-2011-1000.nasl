#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1000. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63992);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id("CVE-2010-3389");
  script_bugtraq_id(44359);
  script_osvdb_id(68808);
  script_xref(name:"RHSA", value:"2011:1000");

  script_name(english:"RHEL 5 : rgmanager (RHSA-2011:1000)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rgmanager package that fixes one security issue, several
bugs, and adds multiple enhancements is now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rgmanager package contains the Red Hat Resource Group Manager,
which provides the ability to create and manage high-availability
server applications in the event of system downtime.

It was discovered that certain resource agent scripts set the
LD_LIBRARY_PATH environment variable to an insecure value containing
empty path elements. A local user able to trick a user running those
scripts to run them while working from an attacker-writable directory
could use this flaw to escalate their privileges via a
specially crafted dynamic library. (CVE-2010-3389)

Red Hat would like to thank Raphael Geissert for reporting this issue.

This update also fixes the following bugs :

* The failover domain 'nofailback' option was not honored if a service
was in the 'starting' state. This bug has been fixed. (BZ#669440)

* PID files with white spaces in the file name are now handled
correctly. (BZ#632704)

* The /usr/sbin/rhev-check.sh script can now be used from within Cron.
(BZ#634225)

* The clustat utility now reports the correct version. (BZ#654160)

* The oracledb.sh agent now attempts to try the 'shutdown immediate'
command instead of using the 'shutdown abort' command. (BZ#633992)

* The SAPInstance and SAPDatabase scripts now use proper directory
name quoting so they no longer collide with directory names like '/u'.
(BZ#637154)

* The clufindhostname utility now returns the correct value in all
cases. (BZ#592613)

* The nfsclient resource agent now handles paths with trailing slashes
correctly. (BZ#592624)

* The last owner of a service is now reported correctly after a
failover. (BZ#610483)

* The /usr/share/cluster/fs.sh script no longer runs the 'quotaoff'
command if quotas were not configured. (BZ#637678)

* The 'listen' line in the /etc/httpd/conf/httpd.conf file generated
by the Apache resource agent is now correct. (BZ#675739)

* The tomcat-5 resource agent no longer generates incorrect
configurations. (BZ#637802)

* The time required to stop an NFS resource when the server is
unavailable has been reduced. (BZ#678494)

* When using exclusive prioritization, a higher priority service now
preempts a lower priority service after status check failures.
(BZ#680256)

* The postgres-8 resource agent now correctly detects failed start
operations. (BZ#663827)

* The handling of reference counts passed by rgmanager to resource
agents now works properly, as expected. (BZ#692771)

As well, this update adds the following enhancements :

* It is now possible to disable updates to static routes by the IP
resource agent. (BZ#620700)

* It is now possible to use XFS as a file system within a cluster
service. (BZ#661893)

* It is now possible to use the 'clustat' command as a non-root user,
so long as that user is in the 'root' group. (BZ#510300)

* It is now possible to migrate virtual machines when central
processing is enabled. (BZ#525271)

* The rgmanager init script will now delay after stopping services in
order to allow time for other nodes to restart them. (BZ#619468)

* The handling of failed independent subtrees has been corrected.
(BZ#711521)

All users of Red Hat Resource Group Manager are advised to upgrade to
this updated package, which contains backported patches to correct
these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rgmanager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rgmanager-2.0.52-21.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rgmanager-2.0.52-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
