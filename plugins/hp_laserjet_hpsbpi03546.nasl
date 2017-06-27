#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89938);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2016-2244");
  script_osvdb_id(135351);
  script_xref(name:"HP", value:"emr_na-c05030353");
  script_xref(name:"IAVB", value:"2016-B-0042");
  script_xref(name:"HP", value:"HPSBPI03546");

  script_name(english:"HP LaserJet Printers Unspecified Information Disclosure (HPSBPI03546)");
  script_summary(english:"Checks the model number and firmware revision.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and firmware revision, the remote HP
LaserJet printer is affected by an unspecified information disclosure
vulnerability. An unauthenticated, remote attacker can exploit this
vulnerability to obtain sensitive information via unspecified vectors.");
  # https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05030353
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30d880c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the HP LaserJet firmware in accordance with the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);
                                                                         # Examples:
product   = get_kb_item_or_exit('www/hp_laserjet/'+port+'/pname');       # HP LaserJet M750
model     = get_kb_item_or_exit('www/hp_laserjet/'+port+'/modelnumber'); # D3L09A
firmware  = get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw_rev');      # 2304061_439474
url       = get_kb_item_or_exit('www/hp_laserjet/'+port+'/url');

full_product = "HP LaserJet " + product + " Model " + model;

parts = split(firmware, sep:"_", keep:FALSE);
firmware_major = parts[0]; 

serial = get_kb_item('www/hp_laserjet/'+port+'/serial');
if (empty_or_null(serial)) serial = "unknown";

affected_models =
  make_list(
    "CZ255A", "CZ256A", "CZ257A", "CZ258A", # M651
    "D3L08A", "D3L09A", "D3L10A",           # M750
    "CZ249A", "CZ250A", "CA251A",           # M680
    "CD644A", "CD645A",                     # M575dn
    "CF116A", "CF117A",                     # M525f
    "CE989A", "CE990A",                     # M601
    "CE991A", "CE992A", "CE993A",           # M602
    "CE994A", "CE995A", "CE996A",           # M603xh
    "CC522A", "CC523A", "CC524A",           # M775
    "CF235A", "CF236A", "CF238A",           # M712xh
    "A2W77A", "A2W78A", "A2W79A",           # M855
    "A2W76A", "A2W75A", "D7P70A", "D7P71A", # M880
    "CF081A", "CF082A", "CF083A",           # M551
    "CD646A",                               # M575c
    "CF367A",                               # M830z
    "CF118A",                               # M525c
    "B3G85A",                               # M630z
    "CZ244A", "CZ245A",                     # M806
    "J7X28A",                               # M630
    "CF066A", "CF067A", "CF068A", "CF069A"  # M725
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
  '\n  Source URL        : ' + url +
  '\n  Installed version : ' + installed_version + ' (' + firmware + ')' +
  '\n  Fixed version     : 3.7.01 (2307851)' +
  '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
