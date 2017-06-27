#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26911);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2007-0061",
    "CVE-2007-0062",
    "CVE-2007-0063",
    "CVE-2007-4058",
    "CVE-2007-4059",
    "CVE-2007-4155",
    "CVE-2007-4496",
    "CVE-2007-4497",
    "CVE-2007-4591",
    "CVE-2007-5023"
  );
  script_bugtraq_id(25110,25118,25131,25441,25728,25729,25732);
  script_osvdb_id(40086, 40093, 40094, 40095, 40096, 40097, 40099, 40100, 42078);

  script_name(english:"VMware Workstation < 5.5.5 and Server < 1.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VMware Workstation"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of VMware Workstation/Server installed on the remote host
is affected by multiple vulnerabilities, including a privelege
elevation vulnerability that allows a guest to take over a host and a
buffer overflow vulnerability in the DHCP daemon. 

The buffer overlflow in the DHCP server may allow a remote attacker to
execute arbitrary code on the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws6/doc/releasenotes_ws6.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/server/doc/releasenotes_server.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 6.0.1/5.5.5 or VMware Server 1.0.4." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(22, 119, 189, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/04");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:server");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_server_win_detect.nasl");
  script_require_ports(139, 445);

  exit(0);
}

version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if ( ( int(v[0]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 5 && int(v[2]) < 5 ) ||
     ( int(v[0]) == 6 && int(v[1]) == 0 && int(v[2]) < 1 ) )
     {
   	security_hole(get_kb_item("SMB/transport"));
	exit(0);
     }
}

version = get_kb_item("VMware/Server/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if ( ( int(v[0]) < 1 ) ||
     ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) )
   security_hole(get_kb_item("SMB/transport"));
}

