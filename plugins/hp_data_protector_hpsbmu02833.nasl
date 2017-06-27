#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66849);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2013-2324",
    "CVE-2013-2325",
    "CVE-2013-2326",
    "CVE-2013-2327",
    "CVE-2013-2328",
    "CVE-2013-2329",
    "CVE-2013-2330",
    "CVE-2013-2331",
    "CVE-2013-2332",
    "CVE-2013-2333",
    "CVE-2013-2334",
    "CVE-2013-2335"
  );
  script_bugtraq_id(
    60299,
    60300,
    60301,
    60302,
    60303,
    60304,
    60306,
    60307,
    60308,
    60309,
    60310,
    60311
  );
  script_osvdb_id(
    93858,
    93859,
    93860,
    93861,
    93862,
    93863,
    93864,
    93865,
    93866,
    93867,
    93868,
    93869
  );
  script_xref(name:"HP", value:"HPSBMU02883");
  script_xref(name:"HP", value:"SSRT101227");
  script_xref(name:"HP", value:"emr_na-c03781657");
  script_xref(name:"EDB-ID", value:"28973");

  script_name(english:"HP Data Protector Multiple RCE Vulnerabilities");
  script_summary(english:"Does a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple remote code
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version and build number, the remote instance of HP
Data Protector is affected by multiple stack-based buffer overflow
conditions in crs.exe when parsing various opcodes. A remote,
unauthenticated attacker can exploit these to execute arbitrary code
in the context of the SYSTEM user or have other unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-121/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-122/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-123/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-124/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-125/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-126/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-127/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-128/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-129/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-130/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-131/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-161/");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03781657
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a263f550");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in the HP advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-114");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Cell Request Service Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_module_versions.nbin");
  script_require_keys("Services/data_protector/cell_server/Version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

version = get_kb_item_or_exit("Services/data_protector/cell_server/Version");
build = get_kb_item("Services/data_protector/cell_server/Build");

internal_build = get_kb_item("Services/data_protector/build");
if(isnull(internal_build)) internal_build = 0;

# unpatched module, major release (referred to as 'MR' by the vendor)
if(isnull(build)) build = 'MR';

# We need OS-specific info in order to reliably determine whether or
# not those systems are vulnerable
hpux_ver = get_kb_item("Host/HP-UX/version");
solaris_ver = get_kb_item("Host/Solaris/Version");
rh_release = get_kb_item("Host/RedHat/release");
sles_release = get_kb_item("Host/SuSE/release");

winver = get_kb_item("SMB/WindowsVersion");
winver1 = get_kb_item("Host/OS/smb");
if(isnull(winver) && !isnull(winver1))
{
  item = eregmatch(pattern:" ([0-9.]+)$", string:winver1);
  if(!isnull(item) && !isnull(item[1]))
    winver = item[1];
}

if (
  (isnull(hpux_ver) || hpux_ver == '') &&
  (isnull(solaris_ver) || solaris_ver == '') &&
  (isnull(rh_release) || rh_release == '') &&
  (isnull(sles_release) || sles_release == '') &&
  (isnull(winver) || winver == '')
) exit(1, "Unable to determine the operating system version running the HP Data Protector service listening on port "+port+".");

vulnerable = FALSE;

# Ignore anything that looks like DP for Unix since it's not mentioned in the
# advisory
if ('SSPUX' >< build)
  vulnerable = FALSE;

else if ((version == "A.06.20" || version == "A.06.21") && internal_build < 408)
{
 # unpatched version == build number (only HP-UX, Solaris, Windows,
 # and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver =="11.31")) ||
   (solaris_ver && (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10")) ||
   (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
   (winver && (winver == '5.2' || winver == '6.0'))
   ) && build == 'MR'
 )
 {
   vulnerable = TRUE;
 }

 # HP-UX security patch (fixed in PHSS_43422)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver == "11.31") &&
   match = eregmatch(pattern:"PHSS_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 43422)
    vulnerable = TRUE;
 }
 # linux security patch (fixed in DPLNX_00243)
 else if (
   (
     (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
     (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release))
   ) &&
   match = eregmatch(pattern:"DPLNX_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 243)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in DPSOL_00510)
 else if (
   solaris_ver &&
   (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10") &&
   match = eregmatch(pattern:"DPSOL_[0]*([1-9][0-9]*)", string:build))
 {
  build_num = int(match[1]);
  if (build_num < 510)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in DPWIN_00632)
 else if (
   winver &&
   (winver == '5.2' || winver == '6.0') &&
   match = eregmatch(pattern:"DPWIN_[0]*([1-9][0-9]*)", string:build)
 )
 {
   build_num = int(match[1]);
   if (build_num < 632)
     vulnerable = TRUE;
 }
}
else if ((version == "A.07.00" || version == "A.07.01") && internal_build < 103)
{
 # unpatched version == build number (only HP-UX, SLES, Windows,
 # and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23") || hpux_ver =="11.31") ||
   (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release)) ||
   (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
   (winver && (winver == '5.2' || winver == '6.0'))
   ) && build == 'MR'
 )
 {
   vulnerable = TRUE;
 }

 # linux security patch (fixed in DPLNX_00235)
 else if (
   (
     (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
     (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release))
   ) &&
   match = eregmatch(pattern:"DPLNX_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 235)
    vulnerable = TRUE;
 }
 # HP-UX security patch (fixed in PHSS_43315)
 else if (
   hpux_ver &&
   (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver == "11.31") &&
   match = eregmatch(pattern:"PHSS_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 43315)
    vulnerable = TRUE;
 }
 # Windows security patch (fixed in DPWIN_00624)
 else if (
   winver &&
   (winver == '5.2' || winver == '6.0') &&
   match = eregmatch(pattern:"DPWIN_[0]*([1-9][0-9]*)", string:build)
 )
 {
   build_num = int(match[1]);
   if (build_num < 624)
     vulnerable = TRUE;
 }
}

if (vulnerable)
{
  if (report_verbosity > 0)
  {
    report = '\n  Cell server version : '+version+
             '\n  Cell server build   : '+build+
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "HP Data Protector Cell Server", port, version + "(build " + build + ")");
}
