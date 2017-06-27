#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/08/15. Deprecated by groupwise_unsupported.nasl, a
# plugin that covers all unsupported groupwise software.

include("compat.inc");

if (description)
{
  script_id(66267);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/18 16:08:47 $");

  script_name(english:"Novell GroupWise Internet Agent Unsupported (deprecated)");
  script_summary(english:"Checks GWIA version.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated in favor of a combined plugin for the
detection of all unsupported GroupWise software. Please use the plugin
groupwise_unsupported.nasl instead.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("groupwise_ia_detect.nasl");
  script_require_keys("SMB/GWIA/Version");

  exit(0);
}

# Deprecated
exit(0, "This plugin has been deprecated. Use groupwise_unsupported.nasl instead.");

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/GWIA/Version');
path = get_kb_item_or_exit('SMB/GWIA/Path');

if (report_paranoia < 2)
{
  services = get_kb_item_or_exit("SMB/svcs");
  if ("GWIA" >!< services) exit(0, "The GWIA service is not running.");
}

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 8)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  register_unsupported_product(product_name:'Novell GroupWise',
                               version:version, cpe_base:"novell:groupwise");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path                 : ' + path +
      '\n  Installed version    : ' + version +
      '\n  Supported version(s) : 8.x / 2012 / 2014\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The Novell GroupWise Internet Agent '+version+' install under '+path+' is currently supported.');
