#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55734);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/10/24 19:04:29 $");

  script_cve_id("CVE-2011-2747");
  script_bugtraq_id(48725);
  script_osvdb_id(73980);
  script_xref(name:"MSVR", value:"MSVR11-008");

  script_name(english:"Google Picasa <= 3.6 Build 105.61 JPEG Image Handling Remote Code Execution");
  script_summary(english:"Checks file version of Picasa");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote Windows host can be exploited to execute
arbitrary code remotely."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Picasa running on the remote host is earlier
than 3.6 Build 105.67.  As such, it reportedly does not properly
handle JPEG image files with invalid properties. 

If a remote attacker can trick a user into opening a specially crafted
JPEG file with the affected application, he could leverage this issue
to cause an application crash or even execute arbitrary code subject
to the user's privileges."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Picasa 3.6 Build 105.67 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

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
fixed_version_ui = "3.6 Build 105.67";

foreach version (versions)
{
  version_ui = get_kb_item_or_exit(kb_base+version+'/Version_UI');

  # nb: we're using file versions for the comparison. And we're
  #     checking for versions less than *or equal to* 3.6.105.61!
  if (ver_compare(ver:version, fix:"3.6.105.61") <= 0)
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
