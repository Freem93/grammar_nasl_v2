#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51463);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_bugtraq_id(45569);
  script_osvdb_id(70181);

  script_name(english:"Rocket Software UniData/UniVerse unirpc32.dll Uni RPC Service Packet Header Remote Overflow");
  script_summary(english:"Checks version of UniData/UniVerse");

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
  script_set_attribute(attribute:"solution", value:"Upgrade to UniData 7.2.8 / UniVerse 10.3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("rocketsoftware_universe_detect.nasl", "rocketsoftware_unidata_detect.nasl");
  script_require_ports("SMB/RocketSoftware/UniVerse/Version", "SMB/RocketSoftware/UniData/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Determine which products are installed.
prod = make_list();

if (get_kb_item("SMB/RocketSoftware/UniVerse/Version"))
{
  prod = make_list(prod, "UniVerse");
}
if (get_kb_item("SMB/RocketSoftware/UniData/installed"))
{
  prod = make_list(prod, "UniData");
}

if (max_index(prod) == 0) exit(0, "Neither UniVerse nor UniData are installed on the remote host.");

# Check each installed product
info = '';

for (i=0; i<max_index(prod); i++)
{
  if (prod[i] == 'UniVerse')
  {
    path = get_kb_item_or_exit("SMB/RocketSoftware/UniVerse/Path");
    version = get_kb_item_or_exit("SMB/RocketSoftware/UniVerse/Version");
    fix = '10.3.9';
    if (ver_compare(ver:version, fix:fix) == -1)
    {
      info += 
        '\n  Product           : UniVerse' +
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
    }
  }
  if (prod[i] == 'UniData')
  {
    installs = get_kb_list('SMB/RocketSoftware/UniData/*/path');
    if (isnull(installs)) debug_print('The SMB/RocketSoftware/UniData/*/path KB list is missing.');
    else
    {
      foreach item (keys(installs))
      {
        ver = item - 'SMB/RocketSoftware/UniData/';
        ver = ver - '/path';
        ver = split(ver, sep:'.', keep:FALSE);

        version = ver[0] + '.' + ver[1] + '.' + ver[2];
        if (ver_compare(ver:version, fix:'7.2.8') == -1)
        {
          info +=
            '\n  Product           : UniData' +
            '\n  Path              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 7.2.8\n';
        }
      }
    }
  }
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item("SMB/transport"), extra:info);
  else security_hole(port:get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected.");
