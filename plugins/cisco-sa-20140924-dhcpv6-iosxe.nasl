#TRUSTED 9d05bd1ea3173ce8470e219c2d5b1e9602cabaf53bf6aa7c4a88a524e26ba4df4c3ae9ce7d08ebb60324d2e4dbb9ae599c980e87c9e8934ac228397e6de193a683f16fca42d9141f3b87243005da1fb1653f199c6bb04f1fd5ac9305e2b5aaba17a0db854d72ca839a80e04538c32343f7aa55c6bda5ad96d39c0e7445be144d7ec5d3a32bb880bea9e73df8224b4a7db899f1770559b4a5457036ec30a8c72c728b39be1a9fb7f16cab94b3ce55aa75623168d0260a3ec703363eef584b4652538bd8c0701185c875f97e4df11f8fa3eb0d7b0a56579706a05c1adc395950d933d54214b7875c79464aec685e0f62cc35c940acfe0b5d0ea268dc9dd872e8f7d9ff30592bc07a0e3e60543303364018da68873ec4b1a6d7b5cc93249807e7cb358e1ebcdca41ef4e1cd1b6f0890528227851b018def5abc1d07a3483d3a6d4d8e88172942167d830b51ede9a1476b9becc5d53c6f833e9638ab88ce5c4a30ec62426ea7610f4a405e67995fddc535cd038527a9c63ea54a0c06b64bf680fe08c157588a1daf86b8b2082e513e0bc21ea0102b50c0e68be049ee4d0cb31478590ccc45a9b77bf6081712946aef0c043fcc69f870106355c3e2126ad6cd31a929c5de31c639d484d41160b15daa51d57e4cccc3a4b7df6ccbdd97faaf819b150b30d71f648fc0ff7358e7f9bf61ea4987f723341724533a56be37fb480778acf6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78028);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3359");
  script_bugtraq_id(70140);
  script_osvdb_id(112042);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum90081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-dhcpv6");

  script_name(english:"Cisco IOS XE Software DHCPv6 DoS (cisco-sa-20140924-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCP version 6 (DHCPv6) implementation due to
improper handling of DHCPv6 packets. A remote attacker can exploit
this issue by sending specially crafted DHCPv6 packets to the
link-scoped multicast address (ff02::1:2) and the IPv6 unicast
address.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d50bca88");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35609");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum90081");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-dhcpv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
cbi = "CSCum90081";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    # DHCPv6
    if (preg(multiline:TRUE, pattern:"^Using pool: DHCPv6-stateful", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
