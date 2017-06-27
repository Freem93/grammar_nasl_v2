#TRUSTED 797ac5660b47365ca78da376f9a83825bed4cd2bf7beb3edcf5ccfda668bdfa13a1069952ad2216a9b6f714b4faa327829c4c150f68bda9202b787ee29727d0f2da3e9558a434ef34fceac78387556077a4270ee5e09f50f9238e900e0f76bdb091b3b14c0d5a1f646b44d7409289954d67ca8971c2db3ec7c0b9b6f5647fa07368ac96923595b0e7f47085b68b5d702b3b9daa13472b8966d2bcf65c6f068ef3b9a51ae12519e13edc0df0fb2c5d5d58a52e9a4ad1140a7eef9be16667d2ad25c3f3f547530acacafb72445fce636b279a29700286468e281634be520741f87ced6ed57c3819f43edaf1b70890f8147c9007f690a263534adc41467ad8072977a1130691d962cd46f00d8f8341da70636d931cfb3051e0129adc8c1a97ea58b5fb4458a6a3cab87b39c9bde2e34f2ac4c0fa400d4e4b8b7cc0426adf1841d5c6f3269dabaafe28e14ecf43526bda03b1a350e5d9f3f9f911b1a51fe2db55f9fbd54bfee98560c5b80c9f72513c747337b17410e9c17b17ab0d14153b53556265a1ceedb69d959f51ebb4453c9b0942622792fb5d398996f0872e84299b7eecfd2ebfc9f8c4c88a06d9463a2154c1b8efb765e775f0c29bb189734b76d97bd9b162c60f868f61fec76cca0519139444c25d6bc8375b930f29b4cea0c25728f65054485217198ffb84d54c4e98d1ba11c5ba70808cf93fd0633976e79764ea481
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83734);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0708");
  script_bugtraq_id(74382);
  script_osvdb_id(121396);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29956");

  script_name(english:"Cisco IOS XE DHCPv6 Server DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCPv6 server implementation due to improper
handling of DHCPv6 packets for SOLICIT messages for Identity
Association for Non-Temporary Addresses (IA-NA) traffic. An
unauthenticated, adjacent attacker can exploit this issue to cause the
device to crash, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38543");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur29956.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCur29956";

if (
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.14.0S"
)
  fixed_ver = "See solution.";
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_binding", "show ipv6 dhcp binding");
  if (check_cisco_result(buf))
  {
    # Output is "" if  no DHCPv6 server
    if (preg(multiline:TRUE, pattern:"^Client: ", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 server is not enabled");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
