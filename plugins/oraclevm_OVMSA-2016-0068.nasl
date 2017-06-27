#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0068.
#

include("compat.inc");

if (description)
{
  script_id(91748);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_name(english:"OracleVM 3.2 : OpenIPMI (OVMSA-2016-0068)");
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

  - ipmitool: fix ipmi command retry shifts replies
    (#863310)

  - ipmitool: added -b, -B, -l and -T options to ipmitool
    man page (#846596)

  - ipmitool: fixed man page documentation for delloem
    setled command (#797050)

  - ipmitool: fixed wrong permissions on ipmievd.pid
    (#834190)

  - ipmitool: updated delloem commands (#797050)

  - ipmitool: fixed exit code of 'ipmitool -o list' command
    (#740780)

  - ipmitool: disabled automatic bridging of SDR readings to
    IPMB in verbose mode (#749796)

  - ipmitool: fixed reporting of usage of various delloem
    subcommands (#658762)

  - added path to /sbin to lsmod and modprobe (#829705)

  - ipmitool: disabled automatic bridging of SDR readings to
    IPMB (#671059)

  - ipmitool: fixed 'ipmitool sol' sending wrong packets due
    to miscalculation of SOL payload size (#675980)

  - ipmitool: fixed 'ipmitool delloem powermonitor' on
    big-endian platforms (#659326)

  - ipmitool: lowered severity of 'Discovered local IPMB
    address XYZ', it's visible only in the most verbose
    output (#674494)

  - ipmitool: fixed 'delloem mac' command on big-endian
    systems (#568676)

  - ipmitool: fixed Kg encryption key setting broken in
    previous version (#656841)

  - ipmitool: fixed crash when processing non-standard
    sensor readings (#550120)

  - fixed OpenIPMI pkgconfig file to include -pthreads when
    needed (#591646)

  - fixed impi service exit codes, 'service ipmi start' now
    succeeds if the service is already started (#619143)

  - ipmitool: fixed crash when receiving error instead of
    sensor data (#580087)

  - ipmitool: properly ignore a bit in sensor event state
    (#616546)

  - ipmitool: fixed a memory leak on receiving SOL ack
    (#616546)

  - ipmitol: fixed reading of sensor state if the BMC
    provides only part of it (#541263)

  - ipmitool: fixed buffer overflow in tsol module (#546386)

  - ipmitool: fixed checking of several command line
    arguments (#514218 #514237)

  - ipmitool: improved error message when wrong
    user/password is supplied (#552458)

  - ipmitool: fixed 'user priv' command, now it does not
    enable IPMI messaging by default (#552459)

  - ipmitool: added 'delloem' command for Dell-specific IPMI
    extensions (#568676)

  - ipmitool: added 'channel setkg' command to set Kg
    encryption key (#503039)

  - ipmitool: added detection of local IPMB address,
    messages to BMC won't be unnecessarily tunneled
    (#636854)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000487.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenIPMI-tools package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:OpenIPMI-tools");
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
if (rpm_check(release:"OVS3.2", reference:"OpenIPMI-tools-2.0.16-16.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenIPMI-tools");
}
