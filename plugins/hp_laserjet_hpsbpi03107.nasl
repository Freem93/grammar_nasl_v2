#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78110);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"emr_na-c04451722");
  script_xref(name:"HP", value:"HPSBPI03107");

  script_name(english:"HP Printers Security Bypass (HPSBPI03107)");
  script_summary(english:"Checks the firmware datecode.");

  script_set_attribute(attribute:"synopsis", value:"The remote printer is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP printer is affected by a security bypass vulnerability.
The included OpenSSL library has a security bypass flaw in the
handshake process. By using a specially crafted handshake, a remote
attacker can force the use of weak keying material. This could be
leveraged for a man-in-the-middle attack.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04451722
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73870238");
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware in accordance with the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
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
  "HP Color LaserJet CM4540 MFP",                                  20140731,
  "HP Color LaserJet CM4540f MFP",                                 20140731,
  "HP Color LaserJet CM4540fskm MFP",                              20140731,
  "HP Color LaserJet CP5525n",                                     20140731,
  "HP Color LaserJet CP5525dn",                                    20140731,
  "HP Color LaserJet CP5525xh",                                    20140731,
  "HP Color LaserJet Enterprise M750n",                            20140731,
  "HP Color LaserJet Enterprise M750dn",                           20140731,
  "HP Color LaserJet Enterprise M750xh",                           20140731,
  "HP Color LaserJet M651n",                                       20140731,
  "HP Color LaserJet M651dn",                                      20140731,
  "HP Color LaserJet M651xh",                                      20140731,
  "HP Color LaserJet M680f",                                       20140731,
  "HP Color LaserJet M680dn",                                      20140731,
  "HP Color LaserJet Flow M680z",                                  20140731,
  "HP LaserJet Enterprise 500 color MFP M575f",                    20140731,
  "HP LaserJet Enterprise 500 color MFP M575dn",                   20140731,
  "HP LaserJet Enterprise 500 MFP M525f",                          20140731,
  "HP LaserJet Enterprise 500 MFP M525dn",                         20140731,
  "HP LaserJet Enterprise 600 M601n",                              20140731,
  "HP LaserJet Enterprise 600 M601dn",                             20140731,
  "HP LaserJet Enterprise 600 M602n",                              20140731,
  "HP LaserJet Enterprise 600 M602dn",                             20140731,
  "HP LaserJet Enterprise 600 M602x",                              20140731,
  "HP LaserJet Enterprise 600 M603n",                              20140731,
  "HP LaserJet Enterprise 600 M603dn",                             20140731,
  "HP LaserJet Enterprise 600 M603xh",                             20140731,
  "HP LaserJet Enterprise MFP M630dn",                             20140731,
  "HP LaserJet Enterprise MFP M630f",                              20140731,
  "HP LaserJet Enterprise MFP M630h",                              20140731,
  "HP LaserJet Enterprise Flow MFP M630z",                         20140731,
  "HP LaserJet Enterprise 700 color M775dn",                       20140731,
  "HP LaserJet Enterprise 700 color M775f",                        20140731,
  "HP LaserJet Enterprise 700 color M775z",                        20140731,
  "HP LaserJet Enterprise 700 color M775z+",                       20140731,
  "HP LaserJet Enterprise 700 M712n",                              20140731,
  "HP LaserJet Enterprise 700 M712dn",                             20140731,
  "HP LaserJet Enterprise 700 M712xh",                             20140731,
  "HP LaserJet Enterprise 800 color M855dn",                       20140731,
  "HP LaserJet Enterprise 800 color M855xh",                       20140731,
  "HP LaserJet Enterprise 800 color M855x+",                       20140731,
  "HP LaserJet Enterprise 800 color MFP M880z",                    20140731,
  "HP LaserJet Enterprise 800 color MFP M880z+",                   20140731,
  "HP LaserJet Enterprise Color 500 M551n",                        20140731,
  "HP LaserJet Enterprise Color 500 M551dn",                       20140731,
  "HP LaserJet Enterprise Color 500 M551xh",                       20140731,
  "HP LaserJet Enterprise color flow MFP M575c",                   20140731,
  "HP LaserJet Enterprise flow M830z Multifunction Printer",       20140731,
  "HP LaserJet Enterprise flow MFP M525c",                         20140731,
  "HP LaserJet Enterprise M4555 MFP",                              20140731,
  "HP LaserJet Enterprise M4555f MFP",                             20140731,
  "HP LaserJet Enterprise M4555fskm MFP",                          20140731,
  "HP LaserJet Enterprise M4555h MFP",                             20140731,
  "HP LaserJet Enterprise M806dn",                                 20140731,
  "HP LaserJet Enterprise M806x+",                                 20140731,
  "HP LaserJet Enterprise MFP M725dn",                             20140731,
  "HP LaserJet Enterprise MFP M725z+",                             20140731,
  "HP LaserJet Enterprise MFP M725z",                              20140731,
  "HP LaserJet Enterprise MFP M725f",                              20140731,
  "HP Scanjet Enterprise 8500 fn1 Document Capture Workstation",   20140731,
  "HP Color LaserJet CP3525",                                      20140722,
  "HP Color LaserJet CP3525n",                                     20140722,
  "HP Color LaserJet CP3525x",                                     20140722,
  "HP Color LaserJet CP3525dn",                                    20140722,
  "HP LaserJet M4345 Multifunction Printer",                       20140722,
  "HP LaserJet M4345x Multifunction Printer",                      20140722,
  "HP LaserJet M4345xm Multifunction Printer",                     20140722,
  "HP LaserJet M4345xs Multifunction Printer",                     20140722,
  "HP LaserJet M5025 Multifunction Printer",                       20140722,
  "HP Color LaserJet CM6040 Multifunction Printer",                20140723,
  "HP Color LaserJet CM6040f Multifunction Printer",               20140723,
  "HP Color LaserJet Enterprise CP4525n",                          20140725,
  "HP Color LaserJet Enterprise CP4525dn",                         20140725,
  "HP Color LaserJet Enterprise CP4525xh",                         20140725,
  "HP Color LaserJet Enterprise CP4025n Printer",                  20140725,
  "HP Color LaserJet Enterprise CP4025dn Printer",                 20140725,
  "HP LaserJet M5035 Multifunction Printer",                       20140722,
  "HP LaserJet M5035x Multifunction Printer",                      20140722,
  "HP LaserJet M5035xs Multifunction Printer",                     20140722,
  "HP LaserJet M9050 Multifunction Printer",                       20140722,
  "HP LaserJet M9040 Multifunction Printer",                       20140722,
  "HP Color LaserJet CM4730 Multifunction Printer",                20140723,
  "HP Color LaserJet CM4730f Multifunction Printer",               20140723,
  "HP Color LaserJet CM4730fsk Multifunction Printer",             20140723,
  "HP Color LaserJet CM4730fm Multifunction Printer",              20140723,
  "HP LaserJet M3035 Multifunction Printer",                       20140722,
  "HP LaserJet M3035xs Multifunction Printer",                     20140722,
  "HP 9250c Digital Sender",                                       20140723,
  "HP LaserJet Enterprise P3015 Printer",                          20140723,
  "HP LaserJet Enterprise P3015d Printer",                         20140723,
  "HP LaserJet Enterprise P3015n Printer",                         20140723,
  "HP LaserJet Enterprise P3015dn Printer",                        20140723,
  "HP LaserJet Enterprise P3015x Printer",                         20140723,
  "HP LaserJet M3027 Multifunction Printer",                       20140722,
  "HP LaserJet M3027x Multifunction Printer",                      20140722,
  "HP LaserJet CM3530 Multifunction Printer",                      20140722,
  "HP LaserJet CM3530fs Multifunction Printer",                    20140722,
  "HP Color LaserJet CP6015dn Printer",                            20140725,
  "HP Color LaserJet CP6015n Printer",                             20140725,
  "HP Color LaserJet CP6015x Printer",                             20140725,
  "HP Color LaserJet CP6015xh Printer",                            20140725,
  "HP Color LaserJet CP6015de Printer",                            20140725,
  "HP LaserJet P4515n Printer",                                    20140723,
  "HP LaserJet P4515tn Printer",                                   20140723,
  "HP LaserJet P4515x Printer",                                    20140723,
  "HP LaserJet P4515xm Printer",                                   20140723,
  "HP Color LaserJet CM6030 Multifunction Printer",                20140723,
  "HP Color LaserJet CM6030f Multifunction Printer",               20140723,
  "HP LaserJet P4015n Printer",                                    20140723,
  "HP LaserJet P4015dn Printer",                                   20140723,
  "HP LaserJet P4015x Printer",                                    20140723,
  "HP LaserJet P4015tn Printer",                                   20140723,
  "HP LaserJet P4014 Printer",                                     20140723,
  "HP LaserJet P4014n Printer",                                    20140723,
  "HP LaserJet P4014dn Printer",                                   20140723
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
    security_warning(
      port:port,
      extra:
        '\n  Model             : ' + model +
        '\n  Serial number     : ' + serial +
        '\n  Installed version : ' + firmware +
        '\n  Fixed version     : ' + update +
        '\n'
    );
  else security_warning(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected since firmware version ' + firmware + ' is installed');
