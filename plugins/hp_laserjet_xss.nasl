#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63523);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2012-3272");
  script_bugtraq_id(56820);
  script_osvdb_id(88136);

  script_name(english:"HP LaserJet XSS Vulnerability");
  script_summary(english:"Checks the firmware datecode");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is an embedded web server for an HP LaserJet
printer.  The version of the firmware reported by the printer is
reportedly affected by a cross-site scripting vulnerability.  An
attacker could exploit this flaw to execute arbitrary script code.");
  # https://h20566.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c03556108-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66a82c9c");
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware in accordance with the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value: "2012/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cm3530");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cm60xx");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cp3525");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cp4xxx");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cp6015");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet_p3015");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet_p4xxx");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/hp_laserjet/pname", "www/hp_laserjet/fw");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:1, embedded:1);
printer_model = get_kb_item_or_exit("www/hp_laserjet/pname");
printer_fw = get_kb_item_or_exit("www/hp_laserjet/fw");

printer_arr = make_array(
                "CM3530", "53.190.9",
                "CM6030", "52.210.9",
                "CM6040", "52.210.9",
                "CP3525", "06.140.3",
                "CP4025", "07.120.6",
                "CP4525", "07.120.6",
                "CP6015", "04.160.3",
                "P3015", "07.140.3",
                "P4014", "04.170.3",
                "P4015", "04.170.3",
                "P4515", "04.170.3"
              );
if (isnull(printer_arr[printer_model])) exit(0, "LaserJet "+printer_model+" is not reported to be an affected model.");


# Check the firmware datecode.
fw_ver = make_array();

if (printer_arr[printer_model] =~ '^[0-9]{8}')
{
  p_fw_ver = ereg_replace(pattern:'([0-9]+)([ \t]+[0-9]+.[0-9]+.[0-9]+)?', replace:"\1", string:printer_fw);
}
else
{
  p_fw_ver = split(ereg_replace(pattern:'([0-9]+)([ \t]+[0-9]+.[0-9]+.[0-9]+)?', replace:"\2", string:printer_fw), sep:".", keep:FALSE);
  fw_ver = split(printer_arr[printer_model], sep:".", keep:FALSE);
}

if ( 
  ( isnull(max_index(p_fw_ver)) && int(p_fw_ver) < int(printer_arr[printer_model])) ||
  max_index(p_fw_ver) &&
  (
    ( int(p_fw_ver[0]) < int(fw_ver[0]) ||
    ( int(p_fw_ver[0]) == int(fw_ver[0]) && int(p_fw_ver[1]) < int(fw_ver[1])) ||
    ( int(p_fw_ver[0]) == int(fw_ver[0]) && int(p_fw_ver[1]) == int(fw_ver[1]) && int(p_fw_ver[2]) < int(fw_ver[2])))
  )
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    info = 
      '\n  Printer model              : LaserJet ' + printer_model +
      '\n  Installed firmware version : ' + join(p_fw_ver, sep:'.') + 
      '\n  Fixed firmware version     : ' + printer_arr[printer_model] + '\n';
    security_warning(port:port, extra:info);
  }
  else security_warning(port:port);
}
else exit(0, 'The LaserJet '+printer_model+' with firmware version ' + join(p_fw_ver, sep:'.') + ' is not affected.');
