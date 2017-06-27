#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60961);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2008-6552", "CVE-2010-3389");

  script_name(english:"Scientific Linux Security Update : rgmanager on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple insecure temporary file use flaws were discovered in
rgmanager and various resource scripts run by rgmanager. A local
attacker could use these flaws to overwrite an arbitrary file writable
by the rgmanager process (i.e. user root) with the output of rgmanager
or a resource agent via a symbolic link attack. (CVE-2008-6552)

It was discovered that certain resource agent scripts set the
LD_LIBRARY_PATH environment variable to an insecure value containing
empty path elements. A local user able to trick a user running those
scripts to run them while working from an attacker-writable directory
could use this flaw to escalate their privileges via a specially
crafted dynamic library. (CVE-2010-3389)

This update also fixes the following bugs :

  - Previously, starting threads could incorrectly include a
    reference to an exited thread if that thread exited when
    rgmanager received a request to start a new thread. Due
    to this issue, the new thread did not retry and entered
    an infinite loop. This update ensures that new threads
    do not reference old threads. Now, new threads no longer
    enter an infinite loop in which the rgmanager enables
    and disables services without failing gracefully.
    (BZ#502872)

  - Previously, nfsclient.sh left temporary
    nfsclient-status-cache-$$ files in /tmp/. (BZ#506152)

  - Previously, the function local_node_name in
    /resources/utils/member_util.sh did not correctly check
    whether magma_tool failed. Due to this issue, empty
    strings could be returned. This update checks the input
    and rejects empty strings. (BZ#516758)

  - Previously, the file system agent could kill a process
    when an application used a mount point with a similar
    name to a mount point managed by rgmanager using
    force_unmount. With this update, the file system agent
    kills only the processes that access the mount point
    managed by rgmanager. (BZ#555901)

  - Previously, simultaneous execution of 'lvchange
    --deltag' from /etc/init.d/rgmanager caused a checksum
    error on High Availability Logical Volume Manager
    (HA-LVM). With this update, ownership of LVM tags is
    checked before removing them. (BZ#559582)

  - Previously, the isAlive check could fail if two nodes
    used the same file name. With this update, the isAlive
    function prevents two nodes from using the same file
    name. (BZ#469815)

  - Previously, the S/Lang code could lead to unwanted
    S/Lang stack leaks during event processing. (BZ#507430)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=2573
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f053de61"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=469815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=502872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=506152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=507430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=516758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=555901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=559582"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rgmanager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"SL4", reference:"rgmanager-1.9.88-2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
