#TRUSTED 86038bb2bbc9d923e8d87ff1ed5623a6187e83f750a540fc0b99b527d88034ae1222d83d3c97329a983090748205682fb82d5a983c34bb17eb73c2ccf7280b2fee45b3ea18bb380bf49ac752662d1cd1c29cdf5c7fc9e06dd34da89de61bdebf5a34d5fd4c51523aa83b4ace564fa02d64192d8b6e8aff0c77ee9554ca899a7f5287bf6878520f035050f0e677708c98b083d56a672bd8bf9c6edadbe3a6da7bd6f6c21c9d35b98ecbefeaa992e4f2b810091f1bcfee58c6c5156c13e601d8a33ca861e114733cfe086ca8194d126f47d2db960997147130001d08278dad2720b398e13e3b307e1b86d34733b95829ae3c6bd9b110b9d08308af3b6ff8681c50e1045a48cbd3395bca781a25053321c7eacfe4b5750b1ba7479587548d541b490793286eb19480bc58634f821710195277abfe03c150e5f33a82eb1decadf6f9b0ceeb809faf7352e5594ee0ae68815312d91adbcf31daff8e3d2211e394f39811db2b7b4a880153037efa0fa9617d5e659323d356f99449d352654b80e220641b7ca86b4210fb662b49c3f2367fcf0cd01b7b197de230ec3139dc15bba0da3614b54660dfc9aae21963c15bcebf7192b095a7267851e7d84ebcdb10800bdc227bfe7cd65c25bdf46c7d846afb17d2e105952d84d28d50ce8f7c870b8eeabf15da32744c023aa222f5d8274da6d1039db097f9fe8e46d36acc462cdf47b53b87
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78029);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3359");
  script_bugtraq_id(70140);
  script_osvdb_id(112042);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum90081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-dhcpv6");

  script_name(english:"Cisco IOS Software DHCPv6 DoS (cisco-sa-20140924-dhcpv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCum90081";
fixed_ver = NULL;

#15.1MR
if (ver == "15.1(3)MR")
  fixed_ver = "Refer to the vendor.";
#15.1MRA
else if (ver == "15.1(3)MRA" || ver == "15.1(3)MRA1" || ver == "15.1(3)MRA2")
  fixed_ver = "15.1(3)MRA3";
#15.1S
else if (ver == "15.1(3)S" || ver == "15.1(3)S0a" || ver == "15.1(3)S1" || ver == "15.1(3)S2" || ver == "15.1(3)S3" || ver == "15.1(3)S4" || ver == "15.1(3)S5a" || ver == "15.1(3)S6")
  fixed_ver = "15.1(3)S7";
#15.2S
else if (ver == "15.2(1)S" || ver == "15.2(1)S1" || ver == "15.2(1)S2" || ver == "15.2(2)S" || ver == "15.2(2)S0a" || ver == "15.2(2)S0c" || ver == "15.2(2)S0d" || ver == "15.2(2)S1" || ver == "15.2(2)S2" || ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S1c" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a" || ver == "15.2(4)S4" || ver == "15.2(4)S4a" || ver == "15.2(4)S5")
  fixed_ver = "15.2(4)S2t or 15.2(4)S6";
#15.2SNG
else if (ver == "15.2(2)SNG")
  fixed_ver = "Refer to the vendor.";
#15.2SNH
else if (ver == "15.2(2)SNH" || ver == "15.2(2)SNH1")
  fixed_ver = "Refer to the vendor.";
#15.2SNI
else if (ver == "15.2(2)SNI")
  fixed_ver = "15.3(3)S4";
#15.3JA
else if (ver == "15.3(3)JA75")
  fixed_ver = "Refer to the vendor.";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
  fixed_ver = "15.3(3)M4";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b" || ver == "15.3(3)S1" || ver == "15.3(3)S1a" || ver == "15.3(3)S2" || ver == "15.3(3)S2a" || ver == "15.3(3)S3")
  fixed_ver = "15.3(3)S4";
#15.4CG
else if (ver == "15.4(1)CG" || ver == "15.4(1)CG1" || ver == "15.4(2)CG")
  fixed_ver = "Refer to the vendor.";
#15.4S
else if (ver == "15.4(1)S" || ver == "15.4(1)S0a" || ver == "15.4(1)S0b" || ver == "15.4(1)S0c" || ver == "15.4(1)S0d" || ver == "15.4(1)S0e" || ver == "15.4(1)S1" || ver == "15.4(1)S2")
  fixed_ver = "15.4(1)S3 or 15.4(2)S";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1" || ver == "15.4(2)T")
  fixed_ver = "15.4(1)T2 or 15.4(2)T1";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


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
