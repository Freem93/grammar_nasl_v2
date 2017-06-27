#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65925);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/11 17:10:19 $");

  script_cve_id("CVE-2009-2285");
  script_bugtraq_id(35451, 58613);
  script_osvdb_id(55265, 91508);
  script_xref(name:"EDB-ID", value:"10205");

  script_name(english:"Google Picasa < 3.9 Build 136.17 Multiple Vulnerabilities");
  script_summary(english:"Windows version check on Picasa");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The photo organizer running on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Picasa running on the remote host is earlier than
3.9 Build 136.17.  As such, it is affected by the following
vulnerabilities:

 - A buffer underflow vulnerability exists in the
   'LZWDecodeCompat' function in the LibTIFF library. An
   attacker could exploit this issue through the use of a
   specially crafted TIFF image, potentially causing a
   denial of service. (CVE-2009-2285)

 - A sign-extension flaw exists that is triggered by the
   'biBitCount' field that is not properly validated when
   processing the BMP color table.  An attacker could
   exploit this issue though a specially crafted BMP image,
   potentially causing a heap-based buffer overflow
   resulting in a denial of service or arbitrary code
   execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.google.com/picasa/answer/53209");
  script_set_attribute(attribute:"solution", value:"Upgrade to Picasa 3.9.0 build 136.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
fix = "3.9.136.17";

foreach version (versions)
{
  version_ui = get_kb_item_or_exit(kb_base+version+'/Version_UI');

  # nb: we're using file versions for the comparison.
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  {
    path = get_kb_item(kb_base+version+'/Path');
    if (isnull(path)) path = 'n/a';

    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 3.9 Build 136.17\n';
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
