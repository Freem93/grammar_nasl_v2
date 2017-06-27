#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36129);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/01/27 00:45:21 $");

  script_cve_id("CVE-2008-4419");
  script_bugtraq_id(33611);
  script_osvdb_id(51830);
  script_xref(name:"IAVT", value:"2009-T-0010");

  script_name(english:"HP LaserJet Web Server Unspecified Admin Component Traversal Arbitrary File Access");
  script_summary(english:"Checks the firmware datecode");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is an embedded web server for an HP LaserJet
printer.  The version of the firmware reported by the printer is
reportedly affected by a directory traversal vulnerability.  Because
the printer caches printed files, an attacker could exploit this in
order to gain access to sensitive information." );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01623905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e066f19" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500986/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500657/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503676/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/510686/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Upgrade the firmware according to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
  script_set_attribute(attribute:"vuln_publication_date", value: "2009/02/04");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/hp_laserjet/pname", "www/hp_laserjet/fw");

  exit(0);
}

include("global_settings.inc");

printer_model = get_kb_item("www/hp_laserjet/pname");
if (isnull(printer_model)) exit(1, "The 'www/hp_laserjet/pname' KB item is missing.");
printer_fw = get_kb_item("www/hp_laserjet/fw");
if (isnull(printer_fw)) exit(1, "The 'www/hp_laserjet/fw' KB item is missing.");

printer_arr = make_array(
                "2410", "20080819",
                "2420", "20080819",
                "2430", "20080819",
                "P3005", "02.043.1",
                "P3015", "06.043.2",
                "P4015", "04.049.0",
                "CP4025", "07.20.7",
                "CP4525", "07.20.7",
                "4250", "08.160.4",
                "4350", "08.160.4",
                "5200", "08.062.0",
                "5550", "7.014.0",
                "9040", "08.112.0",
                "9050", "08.112.0",
                "4345mfp", "09.120.9",
                "4730mfp", "46.200.9",
                "9040mfp", "08.110.9",
                "9050mfp", "08.110.9",
                "9200C",   "09.120.9",
                "9250",    "48.091.3",
                "9500mfp", "08.110.9"
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
  if (report_verbosity > 0)
  {
    info = '\nThe remote LaserJet '+printer_model+' is running firmware version '+printer_fw+'.\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(port:0);
}
