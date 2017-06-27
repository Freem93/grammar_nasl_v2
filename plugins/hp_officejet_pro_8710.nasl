#
# (C) Tenable Network Security, Inc.  
#

include("compat.inc");

if (description)
{ 
  script_id(99591);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_osvdb_id(151466);

  script_name(english:"HP OfficeJet Pro Wi-Fi Direct Support Printer Configuration Unauthenticated Access");
  script_summary(english:"Checks for unauthenticated access to configuration files.");

  script_set_attribute(attribute:"synopsis", value: 
"The remote HP OfficeJet printer is using a default configuration that
allows unauthenticated access to configuration files.");
  script_set_attribute(attribute:"description", value:
"The remote HP OfficeJet Pro printer is using a default configuration
that lacks access controls and authentication for the Wi-Fi Direct
Support feature. An unauthenticated, remote attacker can exploit this
to gain read and write access to the printer configuration in the
embedded web server.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/Feb/10");
  script_set_attribute(attribute:"see_also", value:"http://neseso.com/advisories/NESESO-2017-0111.pdf");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the administrative interface by setting a password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet_pro_8620");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet_pro_8710");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_officejet_web_detect.nbin");
  script_require_keys("hp/officejet/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("hp/officejet/detected");

printer_kbs = get_kb_list_or_exit("hp/officejet/*/model");
ports = make_list();

foreach printer_kb (keys(printer_kbs))
{
  matches = pregmatch(string:printer_kb, pattern:"hp/officejet/([0-9]+)/model");
  if (isnull(matches) || isnull(matches[1]))
    continue;
  port = int(matches[1]);
  ports = make_list(ports, port);
}

# empty list of ports
if (isnull(keys(ports)))
  audit(AUDIT_HOST_NOT, "HP Officejet Printer");

ports = list_uniq(ports);

port = branch(ports);

kb_base = "hp/officejet/" + port + "/";

product = get_kb_item_or_exit(kb_base + "product");
model = get_kb_item_or_exit(kb_base + "model");

# Attempt to get protected configuration page.

conf_file = http_send_recv3(port: port, method: 'GET', item: "/DevMgmt/SecurityDyn.xml", exit_on_fail:true);
if(conf_file[0] =~ '^HTTP/[01]\\.[01] +200 ' )
{
  if('secdyn:SecurityDyn' >< conf_file[2])
  {
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:"The SecurityDyn.xml configuration file is available.");
  }
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, product, port, model);
}
