#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66969);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/03 04:35:49 $");

  script_cve_id("CVE-2012-5220");
  script_bugtraq_id(59488);
  script_osvdb_id(92747);

  script_name(english:"HP Data Protector Local Privilege Escalation");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and build number, the remote version of HP
Data Protector is potentially affected by an unspecified, local
privilege escalation vulnerability.");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03570121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20220731");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patches referenced in HP's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_module_versions.nbin");
  script_require_keys("Services/data_protector/cell_manager/Version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

version = get_kb_item_or_exit("Services/data_protector/cell_manager/Version");
build = get_kb_item("Services/data_protector/cell_manager/Build");

# unpatched module, major release (referred to as 'MR' by the vendor)
if(isnull(build)) build = 'MR';



# We need OS-specific info in order to reliably determine whether or
# not those systems are vulnerable
hpux_ver = get_kb_item("Host/HP-UX/version");
solaris_ver = get_kb_item("Host/Solaris/Version");
rh_release = get_kb_item("Host/RedHat/release");
sles_release = get_kb_item("Host/SuSE/release");

if (
  (isnull(hpux_ver) || hpux_ver == '') &&
  (isnull(rh_release) || rh_release == '') &&
  (isnull(sles_release) || sles_release == '') &&
  (isnull(solaris_ver) || solaris_ver == '')
) exit(1, "Unable to determine the operating system version for the HP Data Protector service listening on port "+port+".");

vulnerable = FALSE;

# Ignore anything that looks like DP for Unix since it's not mentioned in the
# advisory
if ('SSPUX' >< build)
  vulnerable = FALSE;

else if (version == "A.06.20" || version == "A.06.21")
{
 # unpatched version == build number (only HP-UX, Solaris,
 # and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23" || hpux_ver =="11.31")) ||
   (solaris_ver && (solaris_ver == "5.8" || solaris_ver == "5.9" || solaris_ver == "5.10")) ||
   (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
   (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release))
   ) &&
   egrep (pattern:"^[0-9]+", string:build)
 )
 {
   vulnerable = TRUE;
 }

 # linux security patch (fixed in DPLNX_00246)
 else if (
   (
     (hpux_ver && (hpux_ver == '11.11' || hpux_ver == '11.23' || hpux_ver == '11.31')) ||
     (solaris_ver && (solaris_ver == '5.8' || solaris_ver == '5.9' || solaris_ver == '5.10')) ||
     (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
     (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release))
   ) &&
   match = eregmatch(pattern:"DPLNX_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 246)
    vulnerable = TRUE;
 }
}
else if (version == "A.07.00" || version == "A.07.01")
{
 # unpatched version == build number (only HP-UX, SLES,
 # and RHEL affected)
 if (
   (
   (hpux_ver && (hpux_ver == "11.11" || hpux_ver == "11.23") || hpux_ver =="11.31") ||
   (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release)) ||
   (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release))
   ) &&
   egrep (pattern:"^[0-9]+", string:build)
 )
 {
   vulnerable = TRUE;
 }

 # linux security patch (fixed in DPLNX_00245)
 else if (
   (
     (hpux_ver && (hpux_ver == '11.11' || hpux_ver == '11.23' || hpux_ver == '11.31')) ||
     (rh_release && ('release 4' >< rh_release || 'release 5' >< rh_release)) ||
     (sles_release && ('SLES9' >< sles_release || 'SLES10' >< sles_release || 'SLES11' >< sles_release))
   ) &&
   match = eregmatch(pattern:"DPLNX_[0]*([1-9][0-9]*)", string:build)
 )
 {
  build_num = int(match[1]);
  if (build_num < 245)
    vulnerable = TRUE;
 }
}

if (vulnerable)
{
  if (report_verbosity > 0)
  {
    report = '\n  Cell Manager Version : '+version+
             '\n  Cell Manager Build   : '+build+
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "HP Data Protector Cell Manager", port, version + "(build " + build + ")");
}
