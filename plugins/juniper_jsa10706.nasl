#TRUSTED 391fcb6abb3657c0150c2e7a504edfe1758171fa294c511994334330fd595e46ac14803f0a018b9141e61c944b888b6653d901f3c49dce6608e75d228f919cabec2c4134568177aea6523130b2c49193b04081de740c3cc86ed991e38bfe30eb06b8f79bdf00478ef5db9f7364901be54516d587da956736c73d264242ef2e20015d3a0a64c794010f5cda6d3253ddb5fc14eeb6a3b9d641a8cef702bd08220c5a5924c3b7473f14b610f2e390f64ebc14fd78ba5eade8054532d561cd87793536c0b8a745ca4938b331fb8dd0b6ed3ca5c2ec310ed1d6bce770ca4f216b1f4bd6c4a200e2a016fcf4810d541f06dbb52217d3efccbe3bd3478bada13276303908d300edef7dae30954aacc66e5d292d06ff3a43f0e856d781f954a065720916255e7ddc9527b3de9034ce1d6c2c687be7aaea8a04e4948a3639eeab9dc29975cfd96f5d8008b5126579bd1ced9bf32b7253d15f3ba8a621fbc9aaef0800ec50782167f4ea07619e019ed7b25cf7a7c550a24392f901d00f6dbf1093221643cdaf37152ed391b142d825a7b35be3a2f9f0736c8d9776571a920621c2bc9a617d22f9590febd1f9c4be27173b31a60a25f0fe7f7cbe2560ddcf9c5895cace706e4f093453926eeef56e8b6d2798b16c1ef526727c5554fa99499256633033991a06abeefbf9be72fa98c8101c310de0392221a779ac8fa17e004a95866c639d38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86607);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-5361");
  script_osvdb_id(128906);
  script_xref(name:"JSA", value:"JSA10706");

  script_name(english:"Juniper Junos SRX Series FTP ALG ftps-extension TCP Port Exposure (JSA10706)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a flaw in handling the
ftps-extension option when the SRX secures the FTPS server. An
unauthenticated, remote attacker can exploit this flaw to expose TCP
ports for arbitrary data channels.

Note that this issue only affects devices with the FTP Application
Layer Gateway (ALG) enabled with the ftps-extensions option.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10706");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10706.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ('SRX' >!< model) audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3X48'] = '12.3X48-D15';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# FTP ALG w/ FTPS-Extension must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set security alg ftp ftps-extension";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the FTP Application Layer Gateway (ALG) is not configured with the ftps-extensions option');

  buf = junos_command_kb_item(cmd:"show security alg status");
  if (buf)
  {
    pattern = "^\s*FTP\s*:\s*Enabled";
    if (!preg(string:buf, pattern:pattern, multiline:TRUE))
      audit(AUDIT_HOST_NOT,
        'affected because the FTP Application Layer Gateway (ALG) is not enabled');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
