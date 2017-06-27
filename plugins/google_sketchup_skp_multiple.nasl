#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66926);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/09 16:14:41 $");

  script_cve_id("CVE-2013-3664", "CVE-2013-7388");
  script_bugtraq_id(60248, 68451);
  script_osvdb_id(93787);
  script_xref(name:"IAVB", value:"2013-B-0063");

  script_name(english:"Google SketchUp < 13.0.3689 SKP Multiple Vulnerabilities");
  script_summary(english:"Checks version of SketchUp");

  script_set_attribute(attribute:"synopsis", value:
"A 3-D modeling application on the remote Windows host is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google SketchUp installed on the remote Windows host is
earlier than 13.0.3689. As such, it reportedly is affected by multiple
buffer overflows related to the handling of '.SKP' files. Specially
crafted files containing BMP RLE4 compressed textures or MAC Pict
textures can cause the application to crash or execute arbitrary code.");
  # http://support.google.com/sketchup/bin/static.py?hl=en&page=release_notes.cs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32c70014");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/advisories/BINA-20130521A.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.binamuse.com/advisories/BINA-20130521B.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Trimble SketchUp 2013 (13.0.3689) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:sketchup");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

  # below 13.0.3689 is vuln
  if (ver_compare(ver:ver, fix:'13.0.3689', strict:FALSE) < 0)
  {
    name = installs[install];
    version_ui = get_kb_item("SMB/"+vendor+"_SketchUp/"+ver+"/Version_UI");
    vuln++;
    info += '\n  Product           : '+name+
            '\n  Path              : '+path+
            '\n  Installed version : '+version_ui+ ' ('+ver+')' +
            '\n  Fixed version     : Trimble Sketchup 2013 (13.0.3689)\n';
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
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of "+vendor+" SketchUp are";
    else s = " of "+vendor+ " SketchUp is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+info;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
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
