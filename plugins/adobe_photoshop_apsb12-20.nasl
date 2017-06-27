#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61775);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/06/28 04:36:42 $");
    
  script_cve_id("CVE-2012-0275", "CVE-2012-4170");
  script_bugtraq_id(55333, 55372);
  script_osvdb_id(85006, 85437);

  script_name(english:"Adobe Photoshop CS6 Multiple Buffer Overflow Vulnerabilities (APSB12-20)");
  script_summary(english:"Checks Photoshop version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by multiple buffer
overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Photoshop installed on the remote host is less
than CS6 13.0.1.  Such versions are affected by multiple buffer 
overflow vulnerabilities that could lead to code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-29/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-20.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CS6 13.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("SMB/Adobe_Photoshop/Installed");

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
  if(isnull(product_name)) product_name = "Adobe Photoshop";

  verui = get_kb_item('SMB/Adobe_Photoshop/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;
 
  # version 13.x < 13.0.1 Vuln 
  if (ver[0] == 13 && ver[1] == 0 && ver[2] < 1)
  {
    vuln++;
    info += '\n  Product           : '+ product_name+
            '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 13.0.1 \n';
  }
  else info2 += ' and ' + verui;
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
