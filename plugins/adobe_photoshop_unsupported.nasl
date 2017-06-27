#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55816);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_name(english:"Adobe Photoshop Unsupported Version Detection");
  script_summary(english:"Checks versions gathered by local check");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an unsupported version of Adobe Photoshop.");
  script_set_attribute(attribute:"description", value:
"According to its version, at least one install of Adobe Photoshop on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of Adobe Photoshop that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("SMB/Adobe_Photoshop/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "SMB/Adobe_Photoshop/";
get_kb_item_or_exit(kb_base+"Installed");

versions = get_kb_list(kb_base+'Version');
if (isnull(versions)) exit(1, "The '"+kb_base+"Version' KB list is missing.");

info =  '';
info2 = '';
vuln = 0;
foreach version (versions)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item(kb_base+version+'/Path');
  if (isnull(path)) path = 'n/a';

  product_name = get_kb_item(kb_base+version+'/Product');
  if (isnull(product_name)) product_name = "Adobe Photoshop";

  verui = get_kb_item(kb_base+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if (ver[0] < 16)
  {
    register_unsupported_product(product_name:"Adobe Photoshop", version:version, cpe_base:"adobe:photoshop");

    set_kb_item(name:kb_base+version+'/Obsolete', value:TRUE);

    vuln++;
    info += '\n  Product            : '+ product_name+
            '\n  Path               : '+path+
            '\n  Installed version  : '+verui+
            '\n  Supported versions : CC 2015' +
            '\n';
  }
  else
    info2 += " and " + verui;
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Photoshop are";
    else s = " of Adobe Photoshop is";

    report =
      '\nThe following unsupported instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Photoshop "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
