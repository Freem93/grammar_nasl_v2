#TRUSTED 131b4568bf6dfbf20029dc04684168843e07e29057083b94aca1c28e618d04348483dd6af81e13b90c790ff9b54e19c21a81d2935a92dc5c243ea35490964ca6507ab86f8e702b9fd296de0ef305efcfa81bbfa9a51fb43e1509e0e65c6d77888174fc10dd8d71442c58a112894d0dfee23b867491ce41a4d35a2be9b52c5e4cd102dd392883aa9f324f08ed65c893a2ac720a5b77e866e9337e378b69379b329f9575a109307b57b7dd82d813ca243101400f556e5d3ef14dbe4ae51398ca7a0d5a239f2605d92c76b94be0f8c71d0409e3dd165e3024f70222d95a6c881588ccc107fc4ed3c9f11ee3238985b48214f75b91c018c2c1507708f3ad4e2d768b54c25ef04315ef3a322af2207c1ea9ffe160ac64701b129890c253b4b717e546542927d7ffcf49630d7cb63b63402f9d3b38e47e4fd59c04a00cbb730c16e193a4fcc07c8d692ed1d61ae52f87da571b10bc8794c7a9b39be6c00619cbe326a3dbf96af59d4d1540da1d707aea1a06059e6929e2203603198695eade1fd670e50505a39b7fddeda52950bb9f859ad0b91dea5a016fffec3bbdd6e875594b83e3dca0672e85f3aa1b57cdf337feffe31f0a4c2706ecd128f4c9ef96a09fa45904f3836e56838777d850d620faa9594329b635c016a194fc31ca4b2d91fae13b32c4f6955e857274d409fc834602171fb7869e50d19bffe17ceffe14785eca5adb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97944);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3849");
  script_bugtraq_id(96972);
  script_osvdb_id(154052);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-ani");

  script_name(english:"Cisco IOS XE ANI Registrar DoS (cisco-sa-20170320-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
registrar feature due to incomplete input validation of certain
crafted packets. An unauthenticated, adjacent attacker can exploit
this issue, via specially crafted autonomic network channel discovery
packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that are
configured as an autonomic registrar and that have a whitelist
configured.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?206d164a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-ani.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

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
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.10.8aS',
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
  '3.13.2aS',
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
  '3.18.1cSP',
  '3.9.0E',
  '3.9.1E'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_WARNING, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
