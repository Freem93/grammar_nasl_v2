#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62315);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/20 01:09:29 $");

  script_cve_id("CVE-2012-4894", "CVE-2013-3663");
  script_bugtraq_id(55598, 60251);
  script_osvdb_id(85570, 93788);
  script_xref(name:"IAVB", value:"2013-B-0063");
  script_xref(name:"MSVR", value:"MSVR12-015");

  script_name(english:"Google SketchUp < 8.0.14346 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SketchUp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A 3-D modeling application on the remote Windows host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google SketchUp installed on the remote Windows host is
earlier than 8.0.14346.  As such, it reportedly is affected by the
following vulnerabilities:

  - The application fails to handle certain types of '.SKP'
    files. An attacker can exploit this issue by providing a
    specially crafted '.SKP' file to the victim that can
    execute arbitrary code in the context of the
    application. (CVE-2012-4894)

  - An error exists related to the handling of BMP RLE8
    compressed textures that could result in application
    crashes or arbitrary code execution. (CVE-2013-3663)"
  );
  # http://support.google.com/sketchup/bin/static.py?hl=en&page=release_notes.cs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32c70014");
  script_set_attribute(attribute:"see_also", value:"http://binamuse.com/advisories/BINA-20120523.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google SketchUp 8.0 Maintenance 3 (8.0.14346) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:sketchup");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

  # below 8.0.14346 is vuln
  if (ver_compare(ver:ver, fix:'8.0.14346', strict:FALSE) < 0)
  {
    name = installs[install];
    version_ui = get_kb_item("SMB/"+vendor+"_SketchUp/"+ver+"/Version_UI");
    vuln++;
    info += '\n  Product           : '+name+
            '\n  Path              : '+path+
            '\n  Installed version : '+version_ui+ ' ('+ver+')' +
            '\n  Fixed version     : 8.0 Maintenance 3 (8.0.14346)\n';
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
