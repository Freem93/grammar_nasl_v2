#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74269);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2013-4845");
  script_bugtraq_id(64222);
  script_osvdb_id(100857);

  script_name(english:"HP OfficeJet Pro 8500 XSS");
  script_summary(english:"Checks the model/firmware of HP OfficeJet printer");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP OfficeJet printer is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported build information, the firmware running
on the remote HP OfficeJet printer is affected by a cross-site
scripting vulnerability that could allow an attacker to create a
malicious link containing script code that will be executed in the
browser of an unsuspecting user when followed.");
  # http://h20566.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay?docId=emr_na-c04035829-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217250bf");
  script_set_attribute(attribute:"solution", value:"HP has released firmware updates for the affected products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet_pro_8500");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("hp_officejet_web_detect.nbin");
  script_require_keys("hp/officejet/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("hp/officejet/detected");

printer_kbs = get_kb_list_or_exit("hp/officejet/*/model");
ports = make_list();

foreach printer_kb (keys(printer_kbs))
{
  matches = eregmatch(string:printer_kb, pattern:"hp/officejet/([0-9]+)/model");
  if (isnull(matches) || isnull(matches[1]))
    continue;
  port = int(matches[1]);
  ports = make_list(ports, port);
}

# empty list of ports
if (isnull(keys(ports)))
  audit(AUDIT_HOST_NOT, "HP OfficeJet Printer");

ports = list_uniq(ports);

port = branch(ports);

kb_base = "hp/officejet/" + port + "/";

product = get_kb_item_or_exit(kb_base + "product");
model = get_kb_item_or_exit(kb_base + "model");
firmware = get_kb_item_or_exit(kb_base + "firmware");

# from the HP advisory
if (model == "CB022A" ||
    model == "CB023A" ||
    model == "CB025A" ||
    model == "CB793A" ||
    model == "CB794A" ||
    model == "CB862A" ||
    model == "CB874A" ||
    model == "CN539A")
  fixed_firmware = "DLM1FN1344AR";
else
  exit(0, "The " + product + " " + model + " listening on port " + port + " is not affected.");

firmware_build = int(substr(firmware, 6, 9));
fixed_build = int(substr(fixed_firmware, 6, 9));

if (firmware_build >= fixed_build)
  exit(0, "The " + product + " " + model + " running firmware " + firmware + " listening on port " + port + " is not affected.");

set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Printer            : ' + product +
    '\n  Model              : ' + model +
    '\n  Installed firmware : ' + firmware +
    '\n  Fixed firmware     : ' + fixed_firmware +
    '\n';
  security_warning(extra:report, port:port);
}
else security_warning(port);
