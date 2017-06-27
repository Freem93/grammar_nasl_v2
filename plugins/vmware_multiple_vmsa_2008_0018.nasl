#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(34818);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-4915", "CVE-2008-4917");
  script_bugtraq_id(32168, 32597);
  script_osvdb_id(49795, 52704);
  script_xref(name:"VMSA", value:"2008-0018");
  script_xref(name:"VMSA", value:"2008-0019");
  script_xref(name:"Secunia", value:"32612");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2008-0018/VMSA-2008-0019)");
  script_summary(english:"Checks versions of multiple VMware products"); 

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"A VMware product installed on the remote host is affected by multiple
vulnerabilities :

  - A CPU hardware emulation flaw in certain VMware 
    products could allow a virtual CPU to incorrectly 
    handle a Trap flag.  Successful exploitation of this 
    issue could lead to privilege escalation on the guest 
    operating system.  An attacker would need an account on
    the guest operating system and the ability to run 
    applications to exploit this issue. (CVE-2008-4915)

  - By sending a malicious request from the guest operating 
    system to the virtual hardware, it may be possible to 
    cause the virtual hardware to write to an uncontrolled 
    section in the physical memory. (CVE-2008-4917)" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0018.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0019.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

 - VMware Workstation 6.5.0/5.5.9 or higher.
 - VMware Player 2.5.0/1.0.9 or higher.
 - VMware Server 1.0.8 or higher.
 - VMware ACE 2.5.0/1.0.8 or higher." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl",
		      "vmware_player_detect.nasl","vmware_ace_detect.nasl");
  script_require_ports("VMware/Server/Version", "VMware/ACE/Version",
  "VMware/Player/Version", "VMware/Workstation/Version", 139, 445);
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check for VMware ACE.

version = get_kb_item("VMware/ACE/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if (( v[0] == 1  && v[1] == 0 && v[2] < 8 ) ||
     ( v[0] == 2  && v[1] < 5  )
    )
  {
    if (report_verbosity)
    {
      report = string(
         "\n",
         "Version ",version," of VMware ACE is installed on the remote host.",
         "\n"
      );
      security_warning(port:port, extra:report);
    }
    else
       security_warning(port);
  }
}

# Check for VMware Workstation

version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if (( v[0]  < 5 ) ||
     ( v[0] == 5 && v[1]  < 5 ) ||
     ( v[0] == 5 && v[1] == 5 && v[2] < 9 ) ||
     ( v[0] == 6 && v[1] < 5 )
    )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Workstation is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }  	
       else
   	 security_warning(port);
     }
 exit(0);
}

# Check for VMware Server

version = get_kb_item("VMware/Server/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if ( ( v[0]  < 1 ) ||
      ( v[0] == 1  && v[1] == 0 && v[2] < 8 )
    )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Server is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }	
       else
    	security_warning(port);
    }
 exit(0);
}

# Check for VMware Player

version = get_kb_item("VMware/Player/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if ( ( v[0]  < 1 ) ||
      ( v[0] == 1  && v[1] == 0 && v[2] < 9 ) ||
      ( v[0] == 2  && v[1] < 5 )
    )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }
       else
        security_warning(port);
    }
 exit(0);
}
