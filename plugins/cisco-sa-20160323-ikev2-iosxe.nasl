#TRUSTED 2f0eff2364689d5edf16caf1a41955ab0499b474e3a9832cba52370343760d15ae7f94b672680a1a5bef2ec3a352ce16ff0355a87c0468c11b53ec51d192b5ccdda998eabc053fe2860916305eff48fa20709ac4383eb558c168f23051ac7d0d47191f5896fb411883cd22fede61e4023ed4e2e5036ca14ed430840b8059d95dbe0e3b03f687468e0d7c69a50cddef133fa7d9da6c485cd5266e3d7aee7a4eb2540bbecc71a3eca6b1f90eb32ba5754ff49df828711ca0f8b2be0b421eecd3e0ef17db02ce4dfbc005a2dfcdd06b9967bbb2ada4378d43ff7caa49d819be52117aed64c515cdfdbbad8ee536fadce221621ab4193476b7a8b0b5b1c51d82014d79e4d96f0656afaa985baffe70893b70b201a353ca7f256ab857875a7c4951440595db6fd89e568ff967bb56ad1e8ed509ce4b5180a9a7b3f8fb678629eeb4ab8d5145a9979e9bafb69dae2d815a5d266f52c2f5ca69768b045628171ad1f79b71f8d22a261f4e0f5550f74e3c16e479d9d3414204f2d936ae35ca6c8fc88bd6c2af7005d17d20f1d977bc195c8de9c9e49692b07f6249d952b9db4e374877563d67242bf9589fb43e95c3bacfc4ed96c1d610f8e6860e862f85f9da3cd9b55d3324e2c3c6e88fab61874dcf1f0ccda3e430587df624d58746e68a0260610c5c2badead21826aef454a161f52594302a433be492cbacad927df9c1b9ac8f39f0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90356);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/14");

  script_cve_id("CVE-2016-1344");
  script_osvdb_id(136250);
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco IOS XE IKEv2 Fragmentation DoS (cisco-sa-20160323-ios-ikev2)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 2 (IKEv2) subsystem
due to improper handling of fragmented IKEv2 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted UDP packets, to cause the device to reload.

Note that this issue only affects devices with IKEv2 fragmentation
enabled and is configured for any VPN type based on IKEv2.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea61d7e9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux38417. Alternatively, apply the workaround as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.8.1E' ) flag++;
if ( ver == '3.3.0S' ) flag++;
if ( ver == '3.3.1S' ) flag++;
if ( ver == '3.3.2S' ) flag++;
if ( ver == '3.3.0SG' ) flag++;
if ( ver == '3.3.1SG' ) flag++;
if ( ver == '3.3.2SG' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0S' ) flag++;
if ( ver == '3.4.0aS' ) flag++;
if ( ver == '3.4.1S' ) flag++;
if ( ver == '3.4.2S' ) flag++;
if ( ver == '3.4.3S' ) flag++;
if ( ver == '3.4.4S' ) flag++;
if ( ver == '3.4.5S' ) flag++;
if ( ver == '3.4.6S' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.4.7SG' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.3E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.17.0S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;

# Check that IKEv2 fragmentation or IKEv2 is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv2 fragmentation
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ("crypto ikev2 fragmentation" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv2 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux38417' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
