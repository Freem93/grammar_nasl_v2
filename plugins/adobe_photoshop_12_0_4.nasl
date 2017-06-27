#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53632);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/02/07 15:47:32 $");
 
  script_cve_id("CVE-2011-2164");
  script_bugtraq_id(47686);
  script_osvdb_id(72185);
  script_xref(name:"Secunia", value:"44419");

  script_name(english:"Adobe Photoshop CS5 < 12.0.4 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks Photoshop version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Adobe Photoshop CS5 is older than 12.0.4,
and hence affected by multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/downloads/detail.jsp?ftpID=4973");
  script_set_attribute(attribute:"solution", value:"Apply Adobe Photoshop 12.0.4 update or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  # http://blogs.adobe.com/jnack/2011/05/photoshop-12-0-4-update-for-cs5-arrives.html
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("SMB/Adobe_Photoshop/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Adobe_Photoshop/Installed");

vers = get_kb_list('SMB/Adobe_Photoshop/Version');
if (isnull(vers)) exit(1, 'The "SMB/Adobe_Photoshop/Version" KB list is missing.');

info =  '';
info2 = '';
vuln = 0;
foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Adobe_Photoshop/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  product_name = get_kb_item('SMB/Adobe_Photoshop/'+version+'/Product');
  if(isnull(product_name))
    product_name = "Adobe Photoshop";

  verui = get_kb_item('SMB/Adobe_Photoshop/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  # Advisory only talks about CS5, so don't flag 
  # older versions.
  if (ver[0] == 12 && ver[1] == 0 && ver[2] < 4)
  {
    vuln++;
    info += '\n  Product           : '+ product_name+
            '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 12.0.4\n';
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
      '\nThe following vulnerable instance'+s+' installed on the'+
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
