#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63688);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2012-5931");
  script_bugtraq_id(56535);
  script_osvdb_id(87333);
  script_xref(name:"EDB-ID", value:"22737");

  script_name(english:"NetIQ Privileged User Manager regclnt.dll Directory Traversal");
  script_summary(english:"Checks the version of the 'registry agent' package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of the NetIQ Privileged User
Manager 'registry agent' package, the NetIQ Privileged User Manager
'set_log_config' function in regclnt.dll is affected by a directory
traversal flaw that can be exploited to read or write arbitrary files by
sending a specially crafted POST request. 

Note that Nessus did not check for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_novell_netiq_i_adv.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7011385");
  script_set_attribute(attribute:"solution", value:"Apply NetIQ Privileged User Manager 2.3.1 HF2 (2.3.1-2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell NetIQ 2.3.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"patch_publication_date",value:"2012/11/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:privileged_user_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("netiq_pum_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/netiq_pum");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

report = '';

# app runs on port 443 by default, but can be configured to run on port 80
port = get_http_port(default:80);

appname = "NetIQ Privileged User Manager";
kb_appname = "netiq_pum";

install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:TRUE);
dir = install['dir'];

component = 'Admin Interface Package';
 
raw_version = install['ver'];
version = install['ver'];

hf_level = 0;

if ('-' >< version)
{
  item = eregmatch(pattern:"^([0-9.]+)-([0-9]+)$", string:version);
  if (isnull(item)) exit(1, 'Unable to extract hotfix information from version string.');

  hf_level = item[2];
  version = item[1];
}

if (
  ver_compare(ver:version, fix:"2.3.1", strict:FALSE) == -1 ||
  (version == "2.3.1" && hf_level < 1)
)
{
  report = '\n  URL               : ' + build_url(qs:dir, port:port) +  
           '\n  Installed version : ' + version +
           '\n  Fixed version     : 2.3.1-2\n'; 
} 
# may have been patched, check individual package 
else if (version == "2.3.1" && hf_level == 1)
{
  # check if individual packages has been updated
  pkg_version = get_kb_item_or_exit("www/" + port + "/" + kb_appname + "/packages/registry_agent");
  fix = "2.3.1.2";
  
  temp_arr = split(pkg_version, sep:'.' , keep:FALSE); 
  if (max_index(temp_arr) > 4 || max_index(temp_arr) < 3) exit(1, 'Version information is an unexpected length.\n');
  
  pkg_str_version = temp_arr[0] + '.' + temp_arr[1] + '.' + temp_arr[2];
  if (max_index(temp_arr) == 4) pkg_str_version += ('-' + temp_arr[3]);
 
  # for audit trail
  raw_version = pkg_str_version;
  component = 'Registry Agent Package';

  if (
    version =~ "^2\.3\." &&
    ver_compare(ver:pkg_version, fix:fix, strict:FALSE) == -1
  )
  {
      report = '\n  URL               : ' + build_url(qs:dir, port:port) +  
               '\n  Installed version : ' + pkg_str_version +
               '\n  Fixed version     : 2.3.1-2\n';
  }
}

if (report != '')
{    
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname + ' (' + component + ')', build_url(qs:dir, port:port), raw_version);
