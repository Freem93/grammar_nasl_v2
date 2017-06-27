#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");


if(description)
{
 script_id(11710);
 script_version("$Revision: 1.17 $");
 script_bugtraq_id(7857, 7859);
 script_xref(name:"Secunia", value:"8977");
 script_xref(name:"OSVDB", value:"59041");
 script_xref(name:"OSVDB", value:"59042");

 script_name(english:"FlashFXP < 2.1b923 Multiple Remote Overflows");
 script_summary(english:"Determines the presence of FlashFXP");

 script_set_attribute( attribute:"synopsis", value:
"An FTP client with multiple stack buffer overflow vulnerabilities is
installed on the remote Windows host." );
 script_set_attribute( attribute:"description",  value:
"FlashFXP, an FTP client, is installed on the remote host.  This
version is vulnerable to a stack-based buffer overflow attack when
receiving a long response to the PASV command, or when processing a
long host name." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/324387"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to FlashFXP 2.1 build 923 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/10");
 script_cvs_date("$Date: 2014/06/03 21:03:41 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:flashfxp:flashfxp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_dependencies("flashfxp_installed.nasl");
 script_require_keys("SMB/FlashFXP/Installed");

 exit(0);
}

#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/FlashFXP/";
appname = "FlashFXP";

get_kb_item_or_exit(kb_base + 'Installed');

installs = get_kb_list(kb_base + 'Installs/*');
if (isnull(installs)) exit(1, 'The \'' + kb_base + 'Installs KB list is missing.');

info = '';
info2 = '';
vuln = 0;
foreach install (keys(installs))
{
  path = installs[install];
  version = install - (kb_base + 'Installs/');

  fix = '2.1.0.0';
  if (ver_compare(ver:version, fix:fix, strict:TRUE) < 0)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else info2 += ' and ' + version;
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:info);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since ' + appname + ' ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
