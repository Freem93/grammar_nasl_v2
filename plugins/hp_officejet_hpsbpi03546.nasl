#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89939);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2016-2244");
  script_osvdb_id(135351);
  script_xref(name:"HP", value:"emr_na-c05030353");
  script_xref(name:"IAVB", value:"2016-B-0042");
  script_xref(name:"HP", value:"HPSBPI03546");

  script_name(english:"HP OfficeJet Printers Unspecified Information Disclosure (HPSBPI03546)");
  script_summary(english:"Checks the model number and firmware revision.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and firmware revision, the remote HP
OfficeJet printer is affected by an unspecified information disclosure
vulnerability. An unauthenticated, remote attacker can exploit this
vulnerability to obtain sensitive information via unspecified vectors.");
  # https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05030353
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30d880c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the HP OfficeJet firmware in accordance with the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:officejet");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("hp_officejet_web_detect.nbin");
  script_require_keys("hp/officejet/detected");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:TRUE);
                                                                       # Examples :
product   = get_kb_item_or_exit('hp/officejet/' + port + '/product');  # HP Officejet X555
model     = get_kb_item_or_exit('hp/officejet/' + port + '/model');    # C2S11A
firmware  = get_kb_item_or_exit('hp/officejet/' + port + '/firmware'); # 2302908_435004

full_product = "HP OfficeJet " + product + " Model " + model;

parts = split(firmware, sep:"_", keep:FALSE);
firmware_major = parts[0]; 

serial = get_kb_item('hp/officejet/serial');
if (empty_or_null(serial)) serial = "unknown";

affected_models =
  make_list(
    "B5L04A", "B5L05A", "B5L07A", # X585
    "C2S11A", "C2S12A"           # X555
  );

vuln = FALSE;
# Check model
foreach affected_model (affected_models)
{
  if (affected_model == model)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_DEVICE_NOT_VULN, full_product);

# Check firmware revision
#  Only look at the first part of the firmware revision (e.g. 2307497 of 2307497_543950).
#  The last part of the firmware revision changes for each model
affected_firmware = make_array(
  "3.6.3", "2307497",
  "3.6.4", "2307619",
  "3.7",   "2307781",
  "3.7.1", "2307884",
  "3.7.2", "2307939"
);

installed_version = NULL;

foreach affected_version (keys(affected_firmware))
{
  if (affected_firmware[affected_version] == firmware_major)
  {
    installed_version = affected_version;
    break;
  }
}

if (isnull(installed_version)) audit(AUDIT_DEVICE_NOT_VULN, full_product, firmware);

report =
  '\n  Product           : ' + product +
  '\n  Model             : ' + model +
  '\n  Serial number     : ' + serial +
  '\n  Installed version : ' + installed_version + ' (' + firmware + ')' +
  '\n  Fixed version     : 3.7.01 (2307851)' +
  '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
