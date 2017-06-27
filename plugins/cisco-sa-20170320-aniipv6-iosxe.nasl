#TRUSTED 6d876837ab0f10283080e2e79c9d0dba048e474d0398ec3460a0a7c79dd40d9d31822aeffdc966aa58d0cf83f75fb580000ae7a90e74b3b292a12d54a928ac2d7d087c750ffc92ff472708234c45ee6455988df426c76104867960ba44c9a3ab17e730eff355ca4bdacef83f59784e34a0c8a334abe2705e91bb38014ae63e89043dad056792cd16d9b6853663be321e683dd1a116bda3adca58cfc0ec0621b57ae735102fe8c89bf4160462e7f2797024083e955e9e806b21a6f73c2b0c95d1daa0a8cfbdb873c6c33512287e20c1e15d49cbaa5185215b4ff136b77fcebb48a3c54bd88abaefac71f2b4e575e11cc96b0b10be4a884637c92b0765a9b8d08ced1dfc6536bfbb97d4b3fa17a523194c87637712b5978f08449ada861f00e75b0eef8d0f04540ac2f4d3233bf13dcebd636a9617fa1853bb7055006320210e6696a2028002a47388ac9841d00d7b8f9081110272c83dfe4dcfaf11a6b91d1d2f8e9c2a0b5d61c17350d387384d3c4c4ddfbba88b75a0a9ed0a0aed2cbc4519ea4af2bc2a905b4f64eca0e9b895566e7948dbad6623b82a0f9b3084422b8b86afb28060db069ec13afd695042f0555e3c6d5635de8e54b9006c34b663d78b86f204ab9a313a2ee1208f25855eb50b971265eeaaa3c0f86b11657b285ad35b2033c8f26c6b31f7f05c734ee01f74ffe87d540b674d47f00db42557b1c17e6d3202
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97946);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_osvdb_id(154053);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS XE ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
component due to incomplete input validation of certain crafted IPv6
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IPv6 packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that have a
reachable IPv6 interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d249229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-aniipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

affected_versions = [
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4dS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3vS',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.9.0E',
  '3.9.1E'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running and an IPv6 interface is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if ( !empty_or_null(buf) && "no autonomic" >!< buf )
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf2))
          flag = 1;
      }
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_HOLE, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
