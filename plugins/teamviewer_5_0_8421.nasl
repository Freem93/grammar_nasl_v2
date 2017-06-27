#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49175);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/03/18 21:20:19 $");

  script_bugtraq_id(40242);
  script_osvdb_id(64821);
  script_xref(name:"Secunia", value:"39869");

  script_name(english:"TeamViewer Connection Handling Remote Overflow Denial of Service");
  script_summary(english:"Checks version of TeamViewer.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
remote denial of service vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of TeamViewer installed on the remote Windows host is
earlier than 5.0.8421.  Such versions are affected by a remote denial
of service vulnerability when receiving data from clients. 

By sending malformed packets to the server, a remote attacker can
cause CPU usage to stay at 100% for the duration of the connection,
thereby causing responsiveness issues on the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://www.teamviewer.com/download/changelog.aspx");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.0.8421 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value: "2009/02/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed");

  exit(0);
}

include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

get_kb_item_or_exit('SMB/TeamViewer/Installed');

installs = get_kb_list('SMB/TeamViewer/*');

report = NULL;
fixed_version = '5.0.8421.0';
   
foreach install (keys(installs))
{
  if ('Install' >< install) continue;
  version = install - 'SMB/TeamViewer/';

  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    report += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

if(!isnull(report))
{
  if (report_verbosity > 0) security_hole(port:get_kb_item("SMB/transport"), extra:report);
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "No vulnerable TeamViewer installs were detected.");
