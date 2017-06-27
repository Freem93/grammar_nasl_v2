#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(51352);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/04 20:39:08 $");
 
  script_name(english:"Microsoft .NET Framework Service Pack Out of Date");
  script_summary(english:"Checks the collected version.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote system has a software framework installed that is out of
date."
  );
  script_set_attribute(attribute:"description", value:
"The remote system has Microsoft .NET Framework installed. The
installed version either has no service pack installed or the
installed service pack version is out of date."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/318785/en-us");
 # http://support.microsoft.com/lifecycle/search/?sort=PN&alpha=.NET+Framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85e001a9");
  script_set_attribute(attribute:"solution", value:
"Install the latest Microsoft .NET Framework service pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("microsoft_net_framework_installed.nasl");
  script_require_keys("installed_sw/Microsoft .NET Framework");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);

installs = get_installs(app_name:app);

# First checks Windows
net_fw_sp["4.5.2"]       = "0";
net_fw_sp["4.5.1"]       = "0";
net_fw_sp["4.5"]         = "0";
net_fw_sp["4"]           = "0";
net_fw_sp["3.5"]         = "1";
net_fw_sp["3.0"]         = "2";
net_fw_sp["2.0.50727"]   = "2";
net_fw_sp["1.1.4322"]    = "1";
net_fw_sp["1.0.3705"]    = "3";

info = '';

foreach install (installs[1])
{
  ver = install["version"];
  sp = install["SP"];
  if (isnull(sp)) sp = 0;
  if (!isnull(net_fw_sp[ver]) && sp < net_fw_sp[ver])
  {
    info += '  Installed version : Microsoft .NET Framework v' + ver + ' SP ' + sp +'\n' +
            '  Should be         : Microsoft .NET Framework v' + ver + ' SP ' + net_fw_sp[ver] +'\n\n' ;
  } 
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report += '\n' +
      'The following Microsoft .NET Framework version(s) do not have the\n'+
      'latest service pack installed :\n\n'+
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0,"The remote host has the latest Microsoft .NET Framework service packs installed.");
