#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45569);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_bugtraq_id(39111, 39114, 40486);
  script_osvdb_id(63411, 63412, 65361);
  script_xref(name:"EDB-ID", value:"16784");
  script_xref(name:"EDB-ID", value:"19931");
  script_xref(name:"EDB-ID", value:"19932");
  script_xref(name:"Secunia", value:"39212");

  script_name(english:"Novell ZENworks Configuration Management < 10 SP3 Multiple Flaws");
  script_summary(english:"Checks ZENworks version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected
by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"ZENworks Configuration Management, a configuration management
software from Novell, is installed on the remote Windows host. 

According to its version, it is affected by several vulnerabilities : 

  - An unspecified vulnerability in ZCM Preboot Service may
    allow an attacker to execute arbitrary code on the 
    remote system. (TID 7005572)

  - An unspecified vulnerability in ZCM Remote Execution 
    may allow an attacker to execute arbitrary code on the 
    remote system. (TID 7005573)");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7005572");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7005573");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-090/");

  script_set_attribute(attribute:"solution", value: "Upgrade to ZENworks 10 Configuration Management SP3 (10.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell ZENworks Configuration Management File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks Configuration Management Preboot Service 0x06 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

# Get details of the ZCM install.
path = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
ver = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");

# Check whether the installation is vulnerable.
fix = "10.3.0.0";
if (ver_compare(ver:ver, fix:fix) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
  exit(0);
}
else exit(0, "The Novell ZENworks Configuration Management " + ver + " install is not affected.");
