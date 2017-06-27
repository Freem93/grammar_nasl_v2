#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59172);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    "CVE-2012-2027",
    "CVE-2012-2028",
    "CVE-2012-2052",
    "CVE-2012-0275"
  );
  script_bugtraq_id(
    52634,
    53421,
    53464,
    55372
  );
  script_osvdb_id(
    80229,
    81832,
    81861,
    85437
  );
  script_xref(name:"EDB-ID", value:"18633");
  script_xref(name:"EDB-ID", value:"18862");

  script_name(english:"Adobe Photoshop < CS5 / CS5.1 Multiple Arbitrary Code Execution Vulnerabilities (APSB12-11)");
  script_summary(english:"Checks Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is
prior to CS5 (12.0.5) or CS5.1 (12.1.1). It is, therefore, multiple
arbitrary code execution vulnerabilities :

  - Multiple heap-based buffer overflow conditions exist due
    to a failure to properly sanitize user-supplied input
    when decompressing and handling TIFF image files. An
    unauthenticated, remote attacker can exploit these
    issues, by convincing a user to open a specially crafted
    TIFF image file, to execute arbitrary code.
    (CVE-2012-2027, CVE-2012-2028)

  - A buffer overflow condition exists in the U3D.8bi plugin
    due to a failure to properly sanitize user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a file containing a
    specially crafted Collada (.dae) asset element, to
    execute arbitrary code. (CVE-2012-2052)

  - A heap-based buffer overflow condition exists in
    photoshop.exe due to a failure to properly sanitize
    user-supplied input when decompressing a SGI24LogLum
    compressed TIFF image. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted TIFF image file, to execute
    arbitrary code. (CVE-2012-0275)");
  # https://web.archive.org/web/20150222012212/http://protekresearchlab.com/index.php?option=com_content&view=article&id=40&Itemid=40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?268de05d");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-11.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/photoshop/kb/security-update-photoshop.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CS6 (13.0). Alternatively, apply the patch
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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

  # version < 12.0.5 / 12.1.1 Vuln
  if (
    ver[0] < 12 ||
    (
      ver[0] == 12 &&
      (
        (ver[1] == 0 && ver[2] < 5) ||
        (ver[1] == 1 && ver[2] < 1)
      )
    )
  )
  {
    if (ver[0] == 12 && ver[1] == 0) fix = "CS5 (12.0.5) / CS6 (13.0)";
    else if (ver[0] == 12 && ver[1] == 1) fix = "CS5.1 (12.1.1) / CS6 (13.0)";
    else fix = "CS6 (13.0)";

    vuln++;
    info += '\n  Product           : '+ product_name+
            '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : '+fix+'\n';
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
