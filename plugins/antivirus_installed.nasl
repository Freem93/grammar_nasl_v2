#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(16193);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2017/05/02 14:39:08 $");

 script_name(english:"Antivirus Software Check"); # Do not change this
 script_summary(english:"Checks that the remote host has an antivirus.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"An antivirus application is installed on the remote host, and its
engine and virus definitions are up to date.");
 # http://www.tenable.com/blog/auditing-anti-virus-software-without-an-agent
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b145ae41");
 script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/blog/auditing-anti-virus-products-with-nessus");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 script_add_preference(name:"Delay (in days, between 0 and 7) :", type:"entry", value:0);

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_registry_full_access.nasl",
  "smb_enum_services.nasl",
  "kaspersky_installed.nasl",
  "mcafee_installed.nasl",
  "panda_antivirus_installed.nasl",
  "trendmicro_installed.nasl",
  "savce_installed.nasl",
  "bitdefender_installed.nasl",
  "nod32_installed.nasl",
  "sophos_installed.nasl",
  "fcs_installed.nasl",
  "fep_installed.nasl",
  "checkpoint_zonealarm_installed.nasl",
  "trendmicro_serverprotect_installed.nasl",
  "mcafee_vsel_installed.nasl",
  "wmi_fsecure_av_check.nbin",
  "macosx_sophos_installed.nasl",
  "macosx_xprotect_installed.nasl",
  "avg_internet_security_installed.nbin"
 );
 script_require_ports("Services/ssh", 22, 139, 445);

 exit(0);
}

include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

software = make_list(
  "AVG Internet Security",
  "Kaspersky",
  "McAfee",
  "McAfee_VSEL",
  "Norton",
  "Panda",
  "TrendMicro",
  "TrendMicro ServerProtect",
  "SAVCE",
  "BitDefender",
  "NOD32",
  "Sophos",
  "Forefront_Client_Security",
  "Forefront_Endpoint_Protection",
  "F-Secure",
  "SophosOSX",
  "XProtect",
  "Check Point ZoneAlarm"
);

problem_installs = make_list();
port = '';
report = '';

foreach av (software)
{
  if (get_kb_item("Antivirus/" + av + "/installed"))
  {
    info = get_kb_item("Antivirus/" + av + "/description");
    if (info)
    {
        if (!port)
        {
          if ("OSX" >< av || "XProtect" >< av) port = 0;
          else if ("McAfee_VSEL" >< av) port = 0;
          else
          {
            port = get_kb_item("SMB/transport");
            if (!port) port = 445;
          }
        }
        report += '\n' + av + ' :' +
                  '\n' + info;
    }
    else problem_installs = make_list(problem_installs, av);
  }
}


if (report)
{
  security_report_v4(severity:SECURITY_NOTE,port:port, extra:report);
  exit(0);
}
else
{
  if (max_index(problem_installs) == 0) exit(0, "The host does not have an antivirus that Nessus checks for.");
  else if (max_index(problem_installs) == 1) exit(1, join(problem_installs, sep:" & ")+" is installed, but it is not functioning correctly.");
  else exit(1, join(problem_installs, sep:" & ")+" are installed, but they are not functioning correctly.");
}
