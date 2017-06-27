#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0078.
#

include("compat.inc");

if (description)
{
  script_id(91754);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_name(english:"OracleVM 3.2 : sos (OVMSA-2016-0078)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - add patch to remove all sysrq echo commands from
    sysreport.legacy (John Sobecki) [orabug 11061754]

  - comment out rh-upload-core and README.rh-upload-core in
    specfile

  - Strip passwords from grub.conf and /etc/fstab Resolves:
    bz1107751

  - Limit the default set of logs collected for directory
    server Resolves: bz1086736

  - Set global[locking_type=0] when calling lvm2 commands
    Resolves: bz916937

  - Force LC_ALL=C for external commands Resolves: bz1099520

  - Do not verify cluster.conf for each mounted gfs2 file
    system Resolves: bz1098793

  - Fix insecure temporary files usage in gfs2 plugin
    Resolves: bz1099151

  - Suppress libxml2 debug output in gfs2 plugin Resolves:
    bz1098793

  - Use PATH when calling the klist command Resolves:
    bz1029017

  - Add SSSD plugin to collect configuration and logs
    Resolves: bz1018407

  - Update sos UI text to match later releases Resolves:
    bz1065468

  - Free libxml2 bindings in cluster plugin Resolves:
    bz773350

  - Suppress libxml2 debug output in cluster plugin
    Resolves: bz782588

  - Update URLs in README and RPM metadata Resolves:
    bz783423

  - Collect mcelog in hardware plugin Resolves: bz810701

  - Add brctl show and brctl showstp output to networking
    Resolves: bz833406

  - Fix installed-rpms formatting for long package names
    Resolves: bz978444

  - Make ethernet interface detection more robust Resolves:
    bz980177

  - Do not collect kerberos keytab files Resolves: bz1029017

  - Restrict wbinfo to local domain in samba plug-in
    Resolves: bz986975

  - Collect /etc/yaboot.conf in bootloader module Resolves:
    bz977187

  - Sanitize hostname when constructing tar archive names
    Resolves: bz976242

  - Remove anaconda-ks.cfg collection from general plug-in
    Resolves: bz857304

  - Check that the up2date hardware script exists before
    running it Resolves: bz782218

  - Ignore empty globs passed to addCopySpecLimit Resolves:
    bz782247

  - Collect /proc/iomem in the hardware module Resolves:
    bz840981

  - Elide passwords in anaconda-ks.cfg and yum.repos.d
    Resolves: bz857304

  - Fix collection of SELinux data when disabled Resolves:
    bz868008

  - Handle ENOSPC more gracefully Resolves: bz891155

  - Limit size of default sar log file collection Resolves:
    bz891155

  - Do not collect archived process accounting files by
    default Resolves: bz906071

  - Collect /etc/modprobe.d in kernel plug-in Resolves:
    bz958346

  - Collect /etc/idmapd.conf for NFS clients and servers
    Resolves: bz907876

  - Always log plugin exceptions that are not raised to the
    interpreter Resolves: bz717480

  - Ensure relative symlink targets are correctly handled
    when copying Resolves: bz717962

  - Correctly handle libxml2 parser exceptions when reading
    cluster.conf Resolves: bz750573

  - Update Red Hat Certificate System plugin for current
    versions Resolves: bz627416

  - Make single threaded operation default and add
    --multithread to override Resolves: bz708346

  - Support multiple possible locations of VRTSexplorer
    script Resolves: bz565996

  - Collect wallaby dump and inventory information in
    mrggrid plugin Resolves: bz641020

  - Add ethtool pause, coalesce and ring (-a, -c, -g)
    options to network plugin Resolves: bz726421

  - Update MRG grid plugin to collect additional logs and
    configuration Resolves: bz641020

  - Fix collection of symlink destinations when copying
    directory trees Resolves: bz717962

  - Allow plugins to specify non-root symlinks for collected
    command output Resolves: bz716987

  - Ensure custom rsyslog destinations are captured and log
    size limits applied Resolves: bz717167

  - Add basic plugin for Veritas products Resolves: bz565996

  - Do not collect subscription manager keys in general
    plugin Resolves: bz750606

  - Fix gfs2 plugin use of callExtProg API Resolves:
    bz667783

  - Fix exceptions and file naming in gfs2 plugin Resolves:
    bz667783

  - Fix translation for fr locale Resolves: bz641020

  - Add basic Infiniband plugin Resolves: bz673246

  - Add plugin for scsi-target-utils iSCSI target Resolves:
    bz677123

  - Fix handling of TMP environment variable Resolves:
    bz733133

  - Correctly determine kernel version in cluster plugin
    Resolves: bz742567

  - Add libvirt plugin Resolves: bz568635

  - Add gfs2 plugin to supplement cluster data collection
    Resolves: bz667783

  - Add support for collecting Red Hat Subscrition Manager
    configuration Resolves: bz714296

  - Fix rhelVersion and convert all in-tree users to use it
    Resolves: bz710567

  - Add support for --tmp-dir command line option Resolves:
    bz562283

  - Add support for collecting entitlement certificates
    Resolves: bz678666

  - Collect non-standard syslog and rsyslog log files
    Resolves: bz596970

  - Fix up2dateclient path in hardware plugin Resolves:
    bz572353

  - Add plugin to collect rsyslog configuration Resolves:
    bz548616

  - Collect /etc/sysconfig/selinux in SELinux plugin
    Resolves: bz674717

  - Fix parted and dumpe2fs output on s390 Resolves:
    bz645507

  - Truncate files that exceed specified size limit
    Resolves: bz636472

  - Update cluster plugin for group_tool and lockdump
    changes Resolves: bz584060

  - Fix satellite and proxy package detection in rhn plugin
    Resolves: bz590389

  - Add plugin to collect certificate system and pki data
    Resolves: bz635966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000494.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sos package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:sos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"sos-1.7-9.73.0.1.el5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sos");
}
