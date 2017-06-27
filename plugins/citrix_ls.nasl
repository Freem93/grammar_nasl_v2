#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40614);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-2452");
  script_bugtraq_id(34759);
  script_xref(name:"OSVDB", value:"54185");
  script_xref(name:"Secunia", value:"34937");

  script_name(english:"Citrix License Server Licensing Management Console Unspecified Issue");
  script_summary(english:"Checks version of Citrix License Server"); 

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unspecified security vulnerability. "  );
  script_set_attribute(attribute:"description", value:
"Citrix License Server is installed on the remote host.

The version of Citrix License Server on the remote host is
reportedly affected by a security vulnerability involving the
Licensing Management Console."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.citrix.com/article/CTX120742"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Citrix License Server version 11.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/04/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/04/28"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/17"
  );
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:licensing");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_licensing_installed.nasl");
  script_require_keys("SMB/Citrix License Server/Path", "SMB/Citrix License Server Version", "SMB/Citrix License Server/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/Citrix License Server/Path');
version = get_kb_item_or_exit('SMB/Citrix License Server/Version');
build = get_kb_item_or_exit('SMB/Citrix License Server/Build');

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "SMB/Registry/Enumerated KB item is missing.");

fix = '11.6.0.0';
if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The Citrix License Server '+version+' build '+build+' install in '+path+' is not affected.');
