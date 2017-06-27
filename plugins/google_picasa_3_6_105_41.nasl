#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45049);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/12/19 15:50:03 $");

  script_bugtraq_id(38384);
  script_osvdb_id(62535);
  script_xref(name:"Secunia", value:"38435");

  script_name(english:"Google Picasa < 3.6 Build 105.41");
  script_summary(english:"Windows version check on Picasa");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A photo organizer application on the remote Windows host has an 
integer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Picasa running on the remote host reportedly
has an integer overflow vulnerability when processing specially
crafted JPEG files.  This can lead to a heap overflow. 

A remote attacker could exploit this by tricking a user into opening a
maliciously crafted JPEG file, resulting in arbitrary code execution."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Picasa 3.6 Build 105.41 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("google_picasa_installed.nasl");
  script_require_keys("SMB/Google_Picasa/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


app_name = "Google Picasa";
kb_base = "SMB/Google_Picasa/";
get_kb_item_or_exit(kb_base+"Installed");


versions = get_kb_list(kb_base+"Versions");
if (isnull(versions)) exit(1, "The '"+kb_base+"Versions' KB list is missing.");


info = '';
info2 = '';
vuln = 0;
fixed_version = "3.6.105.41";
fixed_version_ui = "3.6 Build 105.41";

foreach version (versions)
{
  version_ui = get_kb_item_or_exit(kb_base+version+'/Version_UI');

  # nb: we're using file versions for the comparison. 
  if (ver_compare(ver:version, fix:fixed_version) < 0)
  {
    path = get_kb_item(kb_base+version+'/Path');
    if (isnull(path)) path = 'n/a';

    vuln++;
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : ' + fixed_version_ui + '\n';
  }
  else info2 += ' and ' + version_ui;
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln == 1) s = ' of ' + app_name + ' is';
    else s = 's of ' + app_name + ' are';

    report = '\n' + 'The following vulnerable instance'+s+' installed on the' +
             '\n' + 'remote host :' +
             '\n' +
             info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since "+app_name+" "+info2+" "+be+" installed.");
}                                                                               
else exit(1, "An unexpected error was encountered - 'info2' is empty.");
