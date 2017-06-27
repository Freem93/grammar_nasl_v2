#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93028);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/08/18 16:08:47 $");

  script_name(english:"Novell GroupWise Unsupported Version Detection");
  script_summary(english:"Checks the version of GroupWise.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Novell GroupWise.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Novell GroupWise
software on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Novell GroupWise that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl", "groupwise_ia_detect.nasl", "groupwise_webaccess_detect.nasl");
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

apps = make_list(
  "Novell GroupWise Client",
  "GroupWise WebAccess", 
  "Novell GroupWise Internet Agent"
  );
versions = {};
installs = {};
lowver = 99;

foreach app (apps){
  install = get_installs(app_name:app);

  foreach install (install[1]){
    if(!empty_or_null(install['version'])){
      installs[app] = install;
    }
    # Given that some agents/features of GroupWise could be left at lower versions
    # we should detect on the lowest version feature.
    if(
      installs[app]['version'] != UNKNOWN_VER && 
      ver_compare(ver:installs[app]['version'], fix:lowver,strict:FALSE) < 0
      ) 
    lowver = installs[app]['version'];
  }
}
ver = split(lowver, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 12)
{
  port = get_kb_item('SMB/transport');
  if(empty_or_null(port)) port = 445;
  
  register_unsupported_product(product_name:'Novell GroupWise',
                               version:lowver, cpe_base:"novell:groupwise");
  report =
    '\n  One or more of the Novell GroupWise products
  installed on this host is an unsupported version.';
  foreach app (keys(installs)){
    report += 
      '\n\n  Product              : ' + app +
      '\n  Path                 : ' + installs[app]['path'] +
      '\n  Installed version    : ' + installs[app]['version'];
  }
  report += 
    '\n\n  Supported version(s) : 2012 / 2014' + 
    '\n  EOL URL              : http://support.novell.com/lifecycle/\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else exit(0, 'The Novell GroupWise software installed is currently supported.');
