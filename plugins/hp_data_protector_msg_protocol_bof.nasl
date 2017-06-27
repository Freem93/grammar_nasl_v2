#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43635);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_cve_id("CVE-2007-2280");
  script_bugtraq_id(37396);
  script_osvdb_id(61206);
  script_xref(name:"TRA", value:"TRA-2009-04");
  script_xref(name:"Secunia", value:"37845");
  script_xref(name:"ZDI", value:"ZDI-09-099");
  script_xref(name:"HP", value:"emr_na-c01124817");
  script_xref(name:"HP", value:"HPSBMA02252");
  script_xref(name:"HP", value:"SSRT061258");

  script_name(english:"HP Data Protector OmniInet.exe MSG_PROTOCOL Command RCE");
  script_summary(english:"Does a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The backup service running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and build number, the HP Data Protector
application running on the remote host is affected by a stack-based
buffer overflow condition in the backup client service daemon
(OmniInet.exe). An unauthenticated, remote attacker can exploit this,
via an MSG_PROTOCOL command with long arguments, to corrupt memory,
resulting in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2009-04");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-099/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Dec/258");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c01124817
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24d0174e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in the HP advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OmniInet.exe MSG_PROTOCOL Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl","hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version", "Services/data_protector/build");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_kb_item("Services/hp_openview_dataprotector");
if (!port) port = 5555;
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

version = get_kb_item_or_exit("Services/data_protector/version");
build = get_kb_item_or_exit("Services/data_protector/build");

if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, "HP Data Protector");

# We need the HP-UX/Solaris version in order to reliably determine whether or
# not those systems are vulnerable
hpux_ver = get_kb_item("Host/HP-UX/version");
solaris_ver = get_kb_item("Host/Solaris/Version");
rh_release = get_kb_item("Host/RedHat/release");
os = get_kb_item("Host/OS");
vulnerable = FALSE;

# Ignore anything that looks like DP for Unix since it's not mentioned in the
# advisory
if ('SSPUX' >< build)
  vulnerable = FALSE;
else if (version == "A.05.50")
{
 # unpatched version == build number (only HP-UX, Solaris, and Windows affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23")) ||
   (solaris_ver && (solaris_ver == "5.7" || solaris_ver == "5.8" || solaris_ver == "5.9")) ||
   (os && 'Windows' >< os)
   ) &&
   egrep (pattern:"^[0-9]+", string:build)
 )
 {
   vulnerable = TRUE;
 }

 # windows patch name (fixed in DPWIN_00359)
 else if (match = eregmatch(pattern:"DPWIN_([0-9]+)", string:build))
 {
  build_num = int(match[1]);
  if (build_num < 359)
    vulnerable = TRUE;
 }
 # HP-UX security patch (fixed in PHSS_37382 and PHSS_37383)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23") &&
   match = eregmatch(pattern:"PHSS_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 37382)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in DPSOL_00321)
 else if (
   solaris_ver &&
   (solaris_ver == "5.7" || solaris_ver == "5.8" || solaris_ver == "5.9") &&
   match = eregmatch(pattern:"DPSOL_([0-9]+)", string:build))
 {
  build_num = int(match[1]);
  if (build_num < 321)
    vulnerable = TRUE;
 }
}
else if (version == "A.06.00")
{
 # unpatched version == build number (all platforms affected for 06.00)
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows security patch (fixed in DPWIN_00329)
 if (match = eregmatch(pattern:"DPWIN_([0-9]+)", string:build))
 {
  build_num = int(match[1]);
  if (build_num < 329)
    vulnerable = TRUE;
 }
 # linux security patch (fixed in DPLNX_00029)
 else if (
    rh_release && 'release 4' >< rh_release &&
    match = eregmatch(pattern:"DPLNX_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 29)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in DPSOL_00294)
 else if (
   solaris_ver &&
   (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10") &&
   match = eregmatch(pattern:"DPSOL_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 294)
    vulnerable = TRUE;
 }
 # HP-UX security patch (fixed in PHSS_36622 and PHSS_36623)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver == "11.31") &&
   match = eregmatch(pattern:"PHSS_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 36622)
    vulnerable = TRUE;
 }
}

if (vulnerable)
{
  report = '\nVersion : '+version+'\nBuild : '+build+'\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN,"HP Data Protector", version, build);
