#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78111);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"emr_na-c04451722");
  script_xref(name:"HP", value:"HPSBPI03107");

  script_name(english:"HP OfficeJet Printer Security Bypass (HPSBPI03107)");
  script_summary(english:"Checks the model/firmware of HP OfficeJet printer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP OfficeJet printer is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP OfficeJet printer is affected by a security bypass
vulnerability. The included OpenSSL library has a security bypass flaw
in the handshake process. By using a specially crafted handshake, a
remote attacker can force the use of weak keying material. This could
be leveraged for a man-in-the-middle attack.");
  # https://h20566.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04451722
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ec99199");
  script_set_attribute(attribute:"solution", value:"HP has released firmware updates for the affected products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet");
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

##
# Strictly checks the firmware versions.
#
# @param  string  Host firmware version
# @param  string  Fixed firmware version
#
# @return -1 if host firmware < fixed firmware
#          0 if host firmware = fixed firmware
#          1 if host firmware > fixed firmware
##
function check_firmware(ver, fix)
{
  local_var vlen, flen, vfield, ffield, i;

  ver = split(ver, sep:'_', keep:FALSE);
  fix = split(fix, sep:'_', keep:FALSE);

  vlen = max_index(ver);
  flen = max_index(fix);
  if (vlen != flen)
    return 0;

  for (i = 0; i < vlen || i < flen; i++)
  {
    vfield = int(ver[i]);
    ffield = int(fix[i]);

    if (vfield < ffield)
      return -1;

    if (vfield > ffield)
      return 1;
  }

  return 0;
}

##
#
# Script starts here.
#
##
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
if (model == "B5L04A" ||
    model == "B5L05A" ||
    model == "B5L07A")
  fixed_firmware = "2302963_436066";
else if (model == "C2S11A" ||
         model == "C2S12A")
  fixed_firmware = "2302963_436074";
else
  exit(0, "The " + product + " " + model + " listening on port " + port + " is not affected.");

if(!egrep(pattern:"^[0-9]+_[0-9]+", string:firmware))
  exit(0, "The " + product + " " + model + " running firmware " + firmware + " listening on port " + port + " does not have the expected firmware format.");

if (check_firmware(ver:firmware, fix:fixed_firmware) >= 0)
  exit(0, "The " + product + " " + model + " running firmware " + firmware + " listening on port " + port + " is not affected.");

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
