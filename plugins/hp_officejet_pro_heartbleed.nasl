#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74270);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"HP OfficeJet Printer Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the model/firmware of HP OfficeJet printer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP OfficeJet printer is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported build information, the firmware running
on the remote HP OfficeJet printer is affected by an out-of-bounds
read error, known as the 'Heartbleed Bug' in the included OpenSSL
version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  # https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04272043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19866791");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"HP has released firmware updates for the affected products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (model == "CN459A")
  fixed_firmware = "BNP1CN1409BR";
else if (model == "CN463A")
  fixed_firmware = "BWP1CN1409BR";
else if (model == "CV037A")
  fixed_firmware = "BZP1CN1409BR";
else if (model == "CN460A")
  fixed_firmware = "LNP1CN1409BR";
else if (model == "CN461A")
  fixed_firmware = "LWP1CN1409BR";
else if (model == "CN598A")
  fixed_firmware = "LZP1CN1409BR";
else if (model == "CR770A")
  fixed_firmware = "FRP1CN1416BR";
else if (model == "CV136A")
  fixed_firmware = "EVP1CN1416BR";
else if (model == "A7F64A" ||
         model == "D7Z36A" ||
         model == "A7F65A" ||
         model == "D7Z37A" ||
         model == "A7F66A" ||
         model == "E2D42A" ||
         model == "E1D36A")
  fixed_firmware = "FDP1CN1416AR";
else
  exit(0, "The " + product + " " + model + " listening on port " + port + " is not affected.");

firmware_build = int(substr(firmware, 6, 9));
fixed_build = int(substr(fixed_firmware, 6, 9));

if (firmware_build >= fixed_build)
  exit(0, "The " + product + " " + model + " running firmware " + firmware + " listening on port " + port + " is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Printer            : ' + product +
    '\n  Model              : ' + model +
    '\n  Installed firmware : ' + firmware +
    '\n  Fixed firmware     : ' + fixed_firmware +
    '\n';
  security_hole(extra:report, port:port);
}
else security_hole(port);
