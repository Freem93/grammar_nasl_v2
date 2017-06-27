#TRUSTED a4261b813cc568a5a87a0c0ece3ee41568e45e445782efb9f1bd4e07aaa6dcc7519a05a3b45a903b6070751bc5e21048e4e2eed2401bb9061cbe4c7142fe9df110ca4176f6c4b41042ad6d634bf5228d9825d48a2499aeea966589eb2e11d67625dc1a91ebad07fb6bb04683e348649f68dda48851ecec80bd06ee58c5c1779049d1dfa32d691d943c03879cb6b77cbfdb761423cd41d73eca4def355aa090a50c6d8f998947196f83e7e975de88e8bac04e613101e57a97a1ea56c010dc62ee259fcf67246e29fecbdf77da56a6503fcffb7884dcf0fb9fe8d38100f9fdb78e42e487af8405478b61cf92ce2287eebb376623ca0caa89741074f7d97d4969cbf3ef7fc8c0ba620cc817de0545bbbec13e011ea65bc0574b3606cbaf412e99b7bdbfbbfdb0f06e2f5c4b73afd7619db273b4d9d37c0079f2a06767e7471c27ffe700e7e6cca047c1d2611173a319286bb751b43594c1952b01cde41be2b4d05281eb226f35c8c144a8f9568fae9cddd107851721f0f1774a7b8fc33621820dad4ad1e4a8b7cea9d7658db62f3cd50a88e333d00c8402b103586e226efc38c8c64f606a717cb76b2ad8c5bb1ce8cab49d301c4c245fa665ff4c7cf7ad76112177a6e7a650cc8fc12e255a275896103431915f978ce4186bc848e6b5a5331fb210076953ebca85e4eadd54faf1cf96fdd2ce43d6c224c51317814918175491adf9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73496);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2714");
  script_bugtraq_id(66760);
  script_osvdb_id(105615);
  script_xref(name:"JSA", value:"JSA10622");

  script_name(english:"Juniper Junos SRX Series flowd DoS (JSA10622)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability due to improper
processing by the Enhanced Web Filtering (EWF). An attacker can
exploit this vulnerability by sending a crafted URL to crash the flow
daemon (flowd) process. Repeated crashes of flowd can result in a
sustained denial of service condition for the device.

Note that this issue only affects SRX series devices with EWF enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10622");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10622.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

model = get_kb_item_or_exit('Host/Juniper/model');
ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-12-17') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R15';
fixes['11.4'] = '11.4R9';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.1X46'] = '12.1X46-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for Web Filtering
override = TRUE;
buf = junos_command_kb_item(cmd:"show security utm web-filtering status");
if (buf)
{
  pattern = "Server status:.*UP$";
  if (!preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because Enhanced Web Filtering is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
