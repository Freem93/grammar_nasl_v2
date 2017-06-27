#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61196);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2010-3389");

  script_name(english:"Scientific Linux Security Update : resource-agents on SL6.x i386/x86_64");
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
"The resource-agents package contains a set of scripts to interface
with several services to operate in a High Availability environment
for both Pacemaker and rgmanager service managers.

It was discovered that certain resource agent scripts set the
LD_LIBRARY_PATH environment variable to an insecure value containing
empty path elements. A local user able to trick a user running those
scripts to run them while working from an attacker-writable directory
could use this flaw to escalate their privileges via a specially
crafted dynamic library. (CVE-2010-3389)

This update also fixes the following bugs :

  - When using the Sybase database and the ASEHAagent
    resource in the cluster.conf file, it was not possible
    to run more than one ASEHAagent per Sybase installation.
    Consequently, a second ASEHA (Sybase Adaptive Server
    Enterprise (ASE) with the High Availability Option)
    agent could not be run. This bug has been fixed and it
    is now possible to use two ASEHA agents using the same
    Sybase installation.

  - The s/lang scripts, which implement internal
    functionality for the rgmanager package, while the
    central_processing option is in use, were included in
    the wrong package. Now, the rgmanager and
    resource-agents packages require each other for
    installation to prevent problems when they are used
    separately.

  - Previously, the oracledb.sh script was using the
    'shutdown abort' command as the first attempt to shut
    down a database. With this update, oracledb.sh first
    attempts a graceful shutdown via the 'shutdown
    immediate' command before forcing the shutdown.

  - Previously, when setting up a service on a cluster with
    a shared IP resource and an Apache resource, the
    generated httpd.conf file contained a bug in the line
    describing the shared IP address (the 'Listen' line).
    Now, the Apache resource agent generates the 'Listen'
    line properly.

  - If a high-availability (HA) cluster service was defined
    with an Apache resource and was named with two words,
    such as 'kickstart httpd', the service never started
    because it could not find a directory with the space
    character in its name escaped. Now, Apache resources
    work properly if a name contains a space as described
    above.

  - When inheritance was used in the cluster.conf file, a
    bug in the /usr/share/cluster/nfsclient.sh file
    prevented it from monitoring NFS exports properly.
    Consequently, monitoring of NFS exports to NFS clients
    resulted in an endless loop. This bug has been fixed and
    the monitoring now works as expected.

  - Previously, the postgres-8 resource agent did not detect
    when a PostgreSQL server failed to start. This bug has
    been fixed and postgres-8 now works as expected in the
    described scenario.

  - When using the Pacemaker resource manager, the fs.sh
    resource agent reported an error condition, if called
    with the 'monitor' parameter and the referenced device
    did not exist. Consequently, the error condition
    prevented the resource from being started. Now, fs.sh
    returns the proper response code in the described
    scenario, thus fixing this bug.

  - Previously, numerous RGManager resource agents returned
    incorrect response codes when coupled with the Pacemaker
    resource manager. Now, the agents have been updated to
    work with Pacemaker properly.

This update also adds the following enhancement :

  - With this update, when the network is removed from a
    node using the netfs.sh resource agent, it now recovers
    faster than previously.

As well, this update upgrades the resource-agents package to upstream
version 3.9.2, which provides a number of bug fixes and enhancements
over the previous version.

All users of resource-agents are advised to upgrade to this updated
package, which corrects these issues and adds these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=1684
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e11e5e9a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected resource-agents and / or resource-agents-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"resource-agents-3.9.2-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"resource-agents-debuginfo-3.9.2-7.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
