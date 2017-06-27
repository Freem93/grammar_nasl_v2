#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51057);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2010-4294","CVE-2010-4297");
  script_bugtraq_id(45166, 45169);
  script_osvdb_id(69590, 69596);
  script_xref(name:"VMSA", value:"2010-0018");
  script_xref(name:"IAVA", value:"2010-A-0168");
  script_xref(name:"Secunia", value:"42480");
  script_xref(name:"Secunia", value:"42481");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2010-0018)");
  script_summary(english:"Checks vulnerable versions of VMware products");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A VMware product (Player, Workstation, Server, or Movie Decoder)
detected on the remote host has one or more of the following
vulnerabilities :

  - A vulnerability in VMware Tools update could allow 
    arbitrary code execution on non-Windows based guest 
    operating systems with root privileges. (CVE-2010-4297)

  - A vulnerability in VMware VMnc Codec could allow 
    arbitrary code execution subject to the privileges
    of the user running the application using the 
    vulnerable codec. (CVE-2010-4294)

In addition to patching, VMware Tools must be manually updated on all
guest VMs in order to completely mitigate certain vulnerabilities. 
Refer to the VMware advisory for more information."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.vmware.com/security/advisories/VMSA-2010-0018");
  script_set_attribute(attribute:"see_also",value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-16");
  script_set_attribute(attribute:"see_also",value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to :

  - VMware Workstation 6.5.5 / 7.1.2 or later.
  - VMware Player 2.5.5 / 3.1.2 or later.
  - VMware Movie Decoder (standalone) 6.5.5/7.1.2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "vmware_workstation_detect.nasl", "vmware_player_detect.nasl", "vmware_server_win_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = kb_smb_transport();
report = '';
vuln = NULL;

# Check if Movie Decoder is installed
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

decoder_installed = FALSE;
foreach name (list)
{
  if (name == 'VMware Movie Decoder')
  {
    decoder_installed = TRUE;
    break;
  }
}

# Check for VMware Workstation
version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if (
  ( int(v[0]) <  6 ) ||
  ( int(v[0]) == 6 && int(v[1]) <  5) ||
  ( int(v[0]) == 6 && int(v[1]) == 5 && int(v[2]) < 5)
 )
 {
   vuln = TRUE;

   report = 
     '\n  Product           : VMware Workstation'+
     '\n  Installed version : '+version+
     '\n  Fixed version     : 6.5.5\n';
 }
 else if (
  (int(v[0]) == 7 && int(v[1]) < 1 ) ||
  (int(v[0]) == 7 && int(v[1]) == 1 && int(v[2]) < 2)
 ) 
 {
   vuln = TRUE;

   report =
     '\n  Product           : VMware Workstation'+
     '\n  Installed version : '+version+
     '\n  Fixed version     : 7.1.2\n';
 }
 else if (isnull(vuln)) vuln = FALSE;
}
else if (decoder_installed)
{
  # If Workstation is not installed, check if the standalone Movie Decoder is
  # present and vulnerable
  if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

  if (
    (hotfix_is_vulnerable(file:"vmnc.dll", version:"6.5.5", dir:"\system32")) || 
    (hotfix_is_vulnerable(file:"vmnc.dll", version:"7.1.2", min_version:"7.0.0", dir:"\system32"))
  )
  {
    vuln = TRUE;
    hf_report = split(hotfix_get_report(), sep:'\n', keep:FALSE);
    report = '\n  Product : VMware Movie Decoder'+
             '\n  ' + hf_report[1]+
             '\n  ' + hf_report[2]+'\n';
  }
  
  hotfix_check_fversion_end();
}

version = get_kb_item("VMware/Server/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  # Flag all server versions <= 2
  if (int(v[0]) <= 2)
  {
    vuln = TRUE;

    report =
      '\n  Product           : VMware Server'+
      '\n  Installed version : '+ version + 
      '\n  Fixed version     : no patches planned.\n';
  }                                                                                                                                                                                                                                                         
  else if (isnull(vuln)) vuln = FALSE;                                                                                                                                                                                                                      
}

# Check for VMware Player
version = get_kb_item("VMware/Player/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (
    ( int(v[0]) < 2 ) ||
    ( int(v[0]) == 2 && int(v[1]) < 5 ) ||
    ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 5)
  )
  {
    vuln = TRUE;
    report +=
      '\n  Product           : VMware Player'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : 2.5.5\n';
  }
  else if ((int(v[0]) == 3 && int(v[1]) < 1) ||
           (int(v[0]) == 3 && int(v[1]) == 1 && int(v[2]) < 2)
          )
  {
    vuln = TRUE;
    report +=
      '\n  Product           : VMware Player'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : 3.1.2\n';
  }
  else if (isnull(vuln)) vuln = FALSE;
}

if (isnull(vuln)) exit(0, "No VMware products were detected on this host.");
if (!vuln) exit(0, "The host is not affected.");

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole();
