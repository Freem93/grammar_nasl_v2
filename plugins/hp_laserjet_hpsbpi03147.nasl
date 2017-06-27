#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78870);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-7875");
  script_bugtraq_id(70863);
  script_osvdb_id(114047);
  script_xref(name:"HP", value:"emr_na-c04483249");
  script_xref(name:"HP", value:"HPSBPI03147");

  script_name(english:"HP LaserJet Printers Remote Unauthorized Access, DoS (HPSBPI03147)");
  script_summary(english:"Checks the firmware datecode.");

  script_set_attribute(attribute:"synopsis", value:"The remote printer is affected by a remote access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP printer is affected by an unspecified flaw that can lead
to unauthorized information access or cause a denial of service.");
  # https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04483249
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fef3fad7");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533858/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware in accordance with the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:color_laserjet_cm3530_mfp");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  # Get the printer model either through pjl or web
  script_dependencies("hp_pjl_version.nbin", "hp_laserjet_detect.nasl");
  script_require_ports("www/hp_laserjet/pname", "pjl/model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Remove and fix words in the printer's name that don't match the list
# on the Web site (designed to reduce false negatives). Also convert the
# name to uppercase and remove spaces to make it as unlikely as possible that
# we miss anything.
function normalize_model(model)
{
  local_var series_to_remove, series, words_to_remove, word;

  model = toupper(model);

  #Remove any the generic series number from product name
  series_to_remove = make_list(' 100 ', ' 300 ', ' 400 ', ' 500 ', ' 600 ', ' 700 ');
  foreach series(series_to_remove)
    model = str_replace(string:model, find:series, replace:' ');

  words_to_remove = make_list( 'COLOR', 'EDGELINE', 'ENTERPRISE', 'FLOW', 'HP', 'HOTSPOT', 'LASERJET', 'MFP', 'MULTIFUNCTION', 'PRINTER', 'PROFESSIONAL', 'PRO', 'SERIES', 'SCANJET', 'TOPSHOT', 'WITH', 'ALL', 'IN', 'ONE', 'DIGITAL', 'SENDER', '-', 'FN1', 'DOCUMENT', 'CAPTURE', 'WORKSTATION' );
  foreach word(words_to_remove)
    model = str_replace(string:model, find:word, replace:'');

  model = str_replace(string:model, find:' ', replace:'');

  return model;
}

port = get_service(svc:"jetdirect", exit_on_fail:TRUE);

model = get_kb_item('pjl/model');
if (!model) model = get_kb_item('www/hp_laserjet/pname');
if (!model) exit(1, "Failed to get the HP model number.");

firmware = int(get_kb_item('pjl/firmware'));
if (!firmware) firmware = int(get_kb_item('www/hp_laserjet/fw'));
if (!firmware) exit(1, "Failed to get the HP firmware version.");

serial = get_kb_item('www/hp_laserjet/serial');
if (!serial) serial = get_kb_item('pjl/serial');
if (!serial) serial = "unknown";


# From support.hp.com searches
signing_firmware = make_array(
 #"HP LaserJet 400 MFP M425dn",     20140731, # <---- uncomment for testing
  "HP Color LaserJet CM3530 Multifunction Printer",                20141010,
  "HP Color LaserJet CM3530fs Multifunction Printer",              20141010
);

# Normalize the names of the models (to make it possible to look them up)
fixed_signing_firmware = make_array();
foreach f(keys(signing_firmware))
{
  fixed_signing_firmware[normalize_model(model:f)] = signing_firmware[f];
}
signing_firmware = fixed_signing_firmware;

# Figure out which firmware update the printer requires
model_norm = normalize_model(model:model);
update = signing_firmware[model_norm];

# If we didn't find it in the list, this plugin doesn't apply
if (isnull(update)) exit(0, "This printer model (" + model + ") does not appear to be affected.");

# Check if the firmware version is vulnerable
if (firmware < update)
{
  if (report_verbosity > 0)
    security_hole(
      port:port,
      extra:
        '\n  Model             : ' + model +
        '\n  Serial number     : ' + serial +
        '\n  Installed version : ' + firmware +
        '\n  Fixed version     : ' + update +
        '\n'
    );
  else security_hole(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected since firmware version ' + firmware + ' is installed');
