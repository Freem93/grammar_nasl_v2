#TRUSTED 84318f73442fc0a1cc2de08e6c37f2f77b8d97db31e9df3d84f4c119521e10a513c2975ea830b0a320d64ce9780a123854d106427af030205dbb77b0f5060d0abf8396e1d701cc492ff22f1aab426f288b19476b0a686ca101b1877cbc9056c11b92c6adf31d6c470a7aa541497b9a40489e89cb665e3f32c9f7076838b050ab0b42353ffa372c5080a2dafc2dc608436a3d2fd02e12d0a27791ba3fa873cac8812f85376bb73d4aa2e17fe05e8968a1c599369664957b35cbfdc30a0089b971490ab70116fad82f33afd58d0d4fd945fc5d2f7e5ae1220f5993b95c7228289847e6c7c0d8311911b38d8847d79fee9a53d5c13983185c8a87938ed6ddb7e935fa84bc08ce6ed06b04affd0fe6ba5a9a27c7e1c50d05c24d1c222c63223be38bb835b10a225f16fd0418b4f90c10d1d2f4113bf8d8486a8ace08e4c6f0c23cdf8b60228546c82f8689d81a8974cc931a8022d15a19aa7449194542758dbb57e4243fab66d843c614b222f5dbd2cddf94c31c800d802a9318a5e8888fdd25c9208ba4e1da210ddc7aca192b9ea910868559c03090ca4df80996cb134631443269a7d9f5f899ab95ce8137c15f121c5be1ea9075b6ca62edbb64429aec34f1756f58cfa422ecb9a15ec79a1ce2cdf7ab0e1de6e233c107a3a931dab3a559551f13ccf46f9532b3d1c9e8f598d565b15667b262aabbc8ca7edde7f5f79fbfe2bcdc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70480);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6014");
  script_bugtraq_id(63391);
  script_osvdb_id(98366);
  script_xref(name:"JSA", value:"JSA10595");

  script_name(english:"Juniper Junos Unnumbered Interface Cache Poisoning Remote DoS and Information Disclosure (JSA10595)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service and information
disclosure vulnerabilities. An adjacent attacker can poison the ARP
cache and create a bogus forwarding table entry for an IP address,
effectively creating a denial of service for that subscriber or
interface or leading to information disclosure as the router answers
any ARP message from any IP address.

Note that these issues only affect devices that have Proxy ARP enabled
on an unnumbered interface.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10595");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10595.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-09-18') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4S15';
fixes['11.4'] = '11.4R9';
fixes['11.4X27'] = '11.4X27.44';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fixes['12.2'] = '12.2R6';
fixes['12.3'] = '12.3R3';
fixes['13.1'] = '13.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if PIM is disabled globally or family or per-interface
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Grab NICs w/ Proxy ARP activated
  lines = split(buf, sep:'\n', keep:FALSE);
  nics  = make_list();

  foreach line (lines)
  {
    pattern = "^set (?:logical-systems \S+ )?interfaces (\S+) unit \S+ proxy-arp ";
    # Check if the NICs w/ Proxy ARP are disabled or deactivated
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
        nics = make_list(nics, matches[1]);
    }
  }
  # Check if any interface is 'unnumbered' (essentially not assigned an IP)
  foreach nic (list_uniq(nics))
  {
    pattern = "^set interfaces " + nic + " .* address ";
    if (!junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }

  if (override) audit(AUDIT_HOST_NOT,
    'affected because Proxy ARP is not enabled on an unnumbered interface');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
