#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60650);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-4579", "CVE-2008-6552");

  script_name(english:"Scientific Linux Security Update : cman on SL5.x i386/x86_64");
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
"Multiple insecure temporary file use flaws were found in
fence_apc_snmp and ccs_tool. A local attacker could use these flaws to
overwrite an arbitrary file writable by a victim running those
utilities (typically root) with the output of the utilities via a
symbolic link attack. (CVE-2008-4579, CVE-2008-6552)

Bug fixes :

  - a buffer could overflow if cluster.conf had more than 52
    entries per block inside the <cman> block. The limit is
    now 1024.

  - the output of the group_tool dump subcommands were NULL
    padded.

  - using device='' instead of label='' no longer causes
    qdiskd to incorrectly exit.

  - the IPMI fencing agent has been modified to time out
    after 10 seconds. It is also now possible to specify a
    different timeout value with the '-t' option.

  - the IPMI fencing agent now allows punctuation in
    passwords.

  - quickly starting and stopping the cman service no longer
    causes the cluster membership to become inconsistent
    across the cluster.

  - an issue with lock syncing caused 'receive_own from'
    errors to be logged to '/var/log/messages'.

  - an issue which caused gfs_controld to segfault when
    mounting hundreds of file systems has been fixed.

  - the LPAR fencing agent now properly reports status when
    an LPAR is in Open Firmware mode.

  - the LPAR fencing agent now works properly with systems
    using the Integrated Virtualization Manager (IVM).

  - the APC SNMP fencing agent now properly recognizes
    outletStatusOn and outletStatusOff return codes from the
    SNMP agent.

  - the WTI fencing agent can now connect to fencing devices
    with no password.

  - the rps-10 fencing agent now properly performs a reboot
    when run with no options.

  - the IPMI fencing agent now supports different cipher
    types with the '-C' option.

  - qdisk now properly scans devices and partitions.

  - cman now checks to see if a new node has state to
    prevent killing the first node during cluster setup.

  - 'service qdiskd start' now works properly.

  - the McData fence agent now works properly with the
    McData Sphereon 4500 Fabric Switch.

  - the Egenera fence agent can now specify an SSH login
    name.

  - the APC fence agent now works with non-admin accounts
    when using the 3.5.x firmware.

  - fence_xvmd now tries two methods to reboot a virtual
    machine.

  - connections to OpenAIS are now allowed from unprivileged
    CPG clients with the user and group of 'ais'.

  - groupd no longer allows the default fence domain to be
    '0', which previously caused rgmanager to hang. Now,
    rgmanager no longer hangs.

  - the RSA fence agent now supports SSH enabled RSA II
    devices.

  - the DRAC fence agent now works with the Integrated Dell
    Remote Access Controller (iDRAC) on Dell PowerEdge M600
    blade servers.

  - fixed a memory leak in cman.

  - qdisk now displays a warning if more than one label is
    found with the same name.

  - the DRAC5 fencing agent now shows proper usage
    instructions for the '-D' option.

  - cman no longer uses the wrong node name when
    getnameinfo() fails.

  - the SCSI fence agent now verifies that sg_persist is
    installed.

  - the DRAC5 fencing agent now properly handles modulename.

  - QDisk now logs warning messages if it appears its I/O to
    shared storage is hung.

  - fence_apc no longer fails with a pexpect exception.

  - removing a node from the cluster using 'cman_tool leave
    remove' now properly reduces the expected_votes and
    quorum.

  - a semaphore leak in cman has been fixed.

  - 'cman_tool nodes -F name' no longer segfaults when a
    node is out of membership.

Enhancements :

  - support for: ePowerSwitch 8+ and LPAR/HMC v3 devices,
    Cisco MDS 9124 and MDS 9134 SAN switches, the virsh
    fencing agent, and broadcast communication with cman.

  - fence_scsi limitations added to fence_scsi man page.

NOTE: openais and pexpect updates are required."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=327
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7805415f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
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
if (rpm_check(release:"SL5", reference:"cman-2.0.115-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cman-devel-2.0.115-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openais-0.80.6-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openais-devel-0.80.6-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pexpect-2.3-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
