#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44330);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/20 19:55:43 $");

  script_cve_id("CVE-2009-4183");
  script_bugtraq_id(37964);
  script_osvdb_id(61955);
  script_xref(name:"Secunia", value:"38306");
  script_xref(name:"HP", value:"emr_na-c01992642");
  script_xref(name:"HP", value:"HPSBMA02502");
  script_xref(name:"HP", value:"SSRT090171");

  script_name(english:"HP Data Protector Unspecified Local Unauthorized Access");
  script_summary(english:"Does a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The backup service running on the remote host is affected by an
unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and build number, the HP Data Protector
application running on the remote host is affected by an unspecified
flaw that allows an local attacker to gain unauthorized access.");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c01992642
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?232d957b");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Jan/268");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in the HP advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl");
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

# We need OS-specific info in order to reliably determine whether or
# not those systems are vulnerable
hpux_ver = get_kb_item("Host/HP-UX/version");
solaris_ver = get_kb_item("Host/Solaris/Version");
os = get_kb_item("Host/OS");
rh_release = get_kb_item("Host/RedHat/release");
vulnerable = FALSE;

# Ignore anything that looks like DP for Unix since it's not mentioned in the
# advisory
if ('SSPUX' >< build)
  vulnerable = FALSE;
else if (version == "A.06.00")
{
 # unpatched version == build number (only HP-UX, Solaris, and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23") || hpux_ver =="11.31") ||
   (solaris_ver && (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10")) ||
   (rh_release && 'release 4' >< rh_release)
   ) &&
   egrep (pattern:"^[0-9]+", string:build)
 )
 {
   vulnerable = TRUE;
 }

 # HP-UX security patch (fixed in PHSS_39015 and PHSS_39016)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver == "11.31") &&
   match = eregmatch(pattern:"PHSS_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 39015)
    vulnerable = TRUE;
 }
 # linux security patch (fixed in DPLNX_00068)
 else if (
   rh_release && 'release 4' >< rh_release &&
   match = eregmatch(pattern:"DPLNX_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 68)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in DPSOL_00366)
 else if (
   solaris_ver &&
   (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10") &&
   match = eregmatch(pattern:"DPSOL_([0-9]+)", string:build))
 {
  build_num = int(match[1]);
  if (build_num < 366)
    vulnerable = TRUE;
 }
}
else if (version == "A.06.10")
{
 # unpatched version == build number (only HP-UX, Solaris, and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23") || hpux_ver =="11.31") ||
   (solaris_ver && (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10")) ||
   (rh_release && 'release 4' >< rh_release)
   ) &&
   egrep (pattern:"^[0-9]+", string:build)
 )
 {
   vulnerable = TRUE;
 }

 # linux security patch (fixed in DPLNX_00076)
 else if (
   rh_release && 'release 4' >< rh_release &&
   match = eregmatch(pattern:"DPLNX_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 76)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in DPSOL_00370)
 else if (
   solaris_ver &&
   (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10") &&
   match = eregmatch(pattern:"DPSOL_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 370)
    vulnerable = TRUE;
 }
 # HP-UX security patch (fixed in PHSS_39510 and PHSS_39511)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver == "11.31") &&
   match = eregmatch(pattern:"PHSS_([0-9]+)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 39510)
    vulnerable = TRUE;
 }
}

if (vulnerable)
{
  report = '\nVersion : '+version+'\nBuild : '+build+'\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN,"HP Data Protector", version, build);
