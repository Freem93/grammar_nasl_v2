#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56713);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/19 14:39:04 $");

  script_cve_id("CVE-2011-2478");
  script_bugtraq_id(48363);
  script_osvdb_id(76715);
  script_xref(name:"MSVR", value:"MSVR11-006");

  script_name(english:"Google SketchUp < 8.0 SKP File Malformed Edge Geometry Handling Remote Code Execution");
  script_summary(english:"Checks version of SketchUp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a 3-D modeling application that is affected by a
remote code execution vulnerability."
);
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google SketchUp installed on the remote Windows host is
earlier than 8.0.  It thus reportedly fails to handle certain types of
invalid geometry described in '.SKP' files and is affected by a buffer
overflow vulnerability.  An attacker can exploit this issue by providing
a specially crafted '.SKP' file to the victim that can execute arbitrary
code in the context of the application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59c67587");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google SketchUp 8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:google_sketchup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("google_sketchup_installed.nasl");
  script_require_ports("SMB/Google_SketchUp/Installed", "SMB/Trimble_SketchUp/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/*_SketchUp/*/Name");

vuln = 0;
info = "";
not_affected_installs = make_list();

foreach install (keys(installs))
{
  if ("/Name" >!< install) continue;

  if ("Google" >< install)
    vendor = "Google";
  else
    vendor = "Trimble";

  preamble_to_remove = "SMB/"+vendor+"_SketchUp/";
  ver = install - preamble_to_remove;
  ver = ver - "/Name";
  path = get_kb_item("SMB/"+vendor+"_SketchUp/"+ver);

  # below 8.0.3117 is vuln
  if (ver_compare(ver:ver, fix:'8.0.3117', strict:FALSE) < 0)
  {
    name = installs[install];
    version_ui = get_kb_item("SMB/"+vendor+"_SketchUp/"+ver+"/Version_UI");
    vuln++;
    info += '\n  Product           : '+name+
            '\n  Path              : '+path+
            '\n  Installed version : '+version_ui+ ' ('+ver+')' +
            '\n  Fixed version     : Google Sketchup 8.0 (8.0.3117)\n';
  }
  else
  {
     not_affected_installs = make_list(
       not_affected_installs,
       vendor + " SketchUp version "+ver+" installed under "+path
     );
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of "+vendor+" SketchUp are";
    else s = " of "+vendor+ " SketchUp is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+info;

    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else
{
  number_of_installs = max_index(not_affected_installs);

  if (number_of_installs == 0)
    audit(AUDIT_NOT_INST, "Google / Trimble SketchUp");
  if (number_of_installs == 1)
    exit(0, "The following install is not affected : " + not_affected_installs[0]);
  else
    exit(0, "The following installs are not affected : " + join(not_affected_installs, sep:'; '));
}
