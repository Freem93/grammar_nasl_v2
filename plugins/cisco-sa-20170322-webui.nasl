#TRUSTED 5f1cfbf99b382a1960595f58d1979229443e4ed68c32c53b97bae4aba18549688bb3026b66d9ae0e280e68c11b74e3ab5ebc88f4c3f1bf1a8cf2c8d698c648a9bfe7032b7ada4eddb341cebb345408ede8d0a0a2500272bf754fff0ff32c992bf3349be632aed39c350128d0959aa0990ba98970aacd36235611c10e753b79fe6ba047cc2acc3747e68fe6d185c0f9f37ae8d89ac32648b6149c0be12954628eb73c69a864c30ed3dd6a1670ad6e1ca1234d6ae5caa3fb5a94c6d19f98189fdcc2b6abacf7fd2f2354e1ade17b32afb1fecd6e908812157089316473a216b6ab64348aa8aa2b1c40210de973bb9a78d4ac99f01ad77eda29f96af6635a965a1e978fce10b471a7c1f9f4c7c42ac45173f9804d7def1dc463884cce42fd87ac25fb898cb1ec199a17e8731b2192e801e9c24a813577c0ced647ee6efc2da5797c59a96fa2f1a7e56256a604747af546670ba1368e1eb5e00cc5f014fc53e03ba6fd78e44b368ca6cac03336d841bec87082feafd54b20a7eb7bca8aaba075d359be96e147022bd5144c89373f441a46aff8d517b08b4938b0a5526c979ca855f32a696f510f11428926d8f38aaa20f5d60011119fd411f9a44d94bcbc7d1f7e96cc99e129e2e7605b3d66ed7bce4845449097fdc7c87e4ffdfac1df8ce1671e44557983be95885457cd23d7cd17d54fbaae839bbe22f37f558d27f9b76a5ad25b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99031);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3856");
  script_bugtraq_id(97007);
  script_osvdb_id(154192);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70353");
  script_xref(name:"IAVA", value:"2017-A-0083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-webui");

  script_name(english:"Cisco IOS XE Web User Interface DoS (cisco-sa-20170322-webui)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the web user interface due to insufficient resource
handling. An unauthenticated, remote attacker can exploit this issue,
by sending a high number of requests to the web user interface, to
cause the device to reload.

Note that for this vulnerability to be exploited, the web user
interface must be enabled and publicly exposed. Typically, it is
connected to a restricted management network. By default, the web user
interface is not enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-webui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072bd138");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup70353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup70353.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (
  ver == "3.1.0S" ||
  ver == "3.1.0SG" ||
  ver == "3.1.1S" ||
  ver == "3.1.1SG" ||
  ver == "3.1.2S" ||
  ver == "3.1.3aS" ||
  ver == "3.1.3S" ||
  ver == "3.1.4aS" ||
  ver == "3.1.4S" ||
  ver == "3.10.0S" ||
  ver == "3.10.1S" ||
  ver == "3.10.1xbS" ||
  ver == "3.10.2S" ||
  ver == "3.10.2tS" ||
  ver == "3.10.3S" ||
  ver == "3.10.4S" ||
  ver == "3.10.5S" ||
  ver == "3.10.6S" ||
  ver == "3.10.7S" ||
  ver == "3.10.8S" ||
  ver == "3.11.0S" ||
  ver == "3.11.1S" ||
  ver == "3.11.2S" ||
  ver == "3.11.3S" ||
  ver == "3.11.4S" ||
  ver == "3.12.0aS" ||
  ver == "3.12.0S" ||
  ver == "3.12.1S" ||
  ver == "3.12.2S" ||
  ver == "3.12.3S" ||
  ver == "3.12.4S" ||
  ver == "3.13.0aS" ||
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.13.2aS" ||
  ver == "3.13.2S" ||
  ver == "3.13.3S" ||
  ver == "3.13.4S" ||
  ver == "3.14.0S" ||
  ver == "3.14.1S" ||
  ver == "3.14.2S" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.0S" ||
  ver == "3.15.1cS" ||
  ver == "3.15.1S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.16.0cS" ||
  ver == "3.16.0S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.1S" ||
  ver == "3.17.0S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.3S" ||
  ver == "3.2.0JA" ||
  ver == "3.2.0SE" ||
  ver == "3.2.0SG" ||
  ver == "3.2.0XO" ||
  ver == "3.2.11SG" ||
  ver == "3.2.1S" ||
  ver == "3.2.1SE" ||
  ver == "3.2.1SG" ||
  ver == "3.2.1XO" ||
  ver == "3.2.2S" ||
  ver == "3.2.2SE" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SE" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.3.0S" ||
  ver == "3.3.0SE" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1S" ||
  ver == "3.3.1SE" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2S" ||
  ver == "3.3.2SE" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.3.3SE" ||
  ver == "3.3.4SE" ||
  ver == "3.3.5SE" ||
  ver == "3.4.0aS" ||
  ver == "3.4.0S" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1S" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2S" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3S" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4S" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5S" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6S" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.0S" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1E" ||
  ver == "3.5.1S" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2E" ||
  ver == "3.5.2S" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3E" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.6.0E" ||
  ver == "3.6.0S" ||
  ver == "3.6.1E" ||
  ver == "3.6.1S" ||
  ver == "3.6.2aE" ||
  ver == "3.6.2S" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.5E" ||
  ver == "3.7.0bS" ||
  ver == "3.7.0E" ||
  ver == "3.7.0S" ||
  ver == "3.7.1E" ||
  ver == "3.7.1S" ||
  ver == "3.7.2E" ||
  ver == "3.7.2S" ||
  ver == "3.7.2tS" ||
  ver == "3.7.3E" ||
  ver == "3.7.3S" ||
  ver == "3.7.4E" ||
  ver == "3.7.4S" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.8.0E" ||
  ver == "3.8.0EX" ||
  ver == "3.8.0S" ||
  ver == "3.8.1E" ||
  ver == "3.8.1S" ||
  ver == "3.8.2E" ||
  ver == "3.8.2S" ||
  ver == "3.9.0E" ||
  ver == "3.9.0S" ||
  ver == "3.9.1S" ||
  ver == "3.9.2S"
)
{
  flag++;
}

cmds = make_list();
# Check if the web user interface is enabled and configured
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include http|transport","show running-config | include http|transport");
  if (check_cisco_result(buf))
  {
    if (
      ("transport-map type persistent webui" >< buf) &&
      ("transport type persistent webui input" >< buf) &&
      ("ip http server" >< buf || "ip http secure-server" >< buf)
    )
    {
      cmds = make_list(cmds, "show running-config | include http|transport");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCup70353",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
