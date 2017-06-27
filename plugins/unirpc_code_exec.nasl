# @DEPRECATED@
#
# This script has been deprecated as remote version information
# is no longer accurate; eg, version 7.2.12 is reported as 7.2.0
#
# Disabled on 2012/01/04.

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51575);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_bugtraq_id(45569);
  script_osvdb_id(70181);

  script_name(english:"Rocket Software UniRPC Service Packet Header Remote Overflow (uncredentialed check)");
  script_summary(english:"Checks version of UniData/UniVerse collected remotely");

  script_set_attribute(attribute:"synopsis", value:
"A database application installed on the remote host is affected by a
buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its reported version, the Rocket Software UniVerse or
UniData install on the remote Windows host is affected by a buffer
overflow vulnerability.  The application fails to properly validate a
size value in a RPC packet header before using it to determine the
number of bytes to receive. 

An unauthenticated, remote attacker can exploit this to execute
arbitrary code on the remote host with SYSTEM level privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-294/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Dec/597");
  script_set_attribute(attribute:"solution", value:"Upgrade to UniData 7.2.8 / UniVerse 10.3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/19");
   script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("unirpc_get_interfaces.nbin");
  script_require_ports("Services/UniRPC");

  exit(0);
}

# Deprecated.
exit(0, "Newer versions of Unidata do not support accurate, remote version information reporting.");

include("global_settings.inc");
include("misc_func.inc");

# Figure out which port(s) to use
port = get_service(svc:'UniRPC', default:31438, exit_on_fail:TRUE);

# Get a path if we have one
path = get_kb_item("RocketSoftware/UniRPC/"+port+"/udadmin72/InstallPath");
if (path) path = '\n  Path              : ' + path;
else path = '';

# Get the version of UniVerse, if it's running
universe = get_kb_item("RocketSoftware/UniRPC/"+port+"/uvcs/Version");
if (universe)
{
  spl = split(universe, sep:':', keep:FALSE);
  version = spl[1];

  fix = '10.3.9';
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      info = 
        '\n  Product           : UniVerse (' + spl[0] + ')' + 
        path + 
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_hole(port:port, extra:info);
    }
    else security_hole(port);
    exit(0);
  }

  # Since UniVerse is running, it doesn't matter if UniData is - they use the same RPC interface
  exit(0, "UniVerse ("+spl[0]+") "+version+" is listening on port "+port+" and not affected.");
}

unidata = get_kb_item("RocketSoftware/UniRPC/"+port+"/udcs/Version");
if(unidata)
{
  spl = split(unidata, sep:':', keep:FALSE);
  version = spl[1];
  fix = '7.2.8';
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      info = 
        '\n  Product           : UniData (' + spl[0] + ')' + 
        path + 
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_hole(port:port, extra:info);
    }
    else security_hole(port);
    exit(0);
  }

  exit(0, "UniData ("+spl[0]+") "+version+" is listening on port "+port+" and not affected.");
}

exit(0, "The UniRPC service listening on port "+port+" is not affected.");
