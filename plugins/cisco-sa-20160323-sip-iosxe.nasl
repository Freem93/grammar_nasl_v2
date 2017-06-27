#TRUSTED a467620be10ee8f0e589dca7f6fc418fc34f5066bf18afca1b21c0128ac0a3151eb9c1e5b6507623c31e40ff74fac5da8ff2aa57e75036ff9d5a8c359e16c817c38c6d3dd39efe1f644985bb8f1584063fa50842230101b906f43a9f7189634385d74935957ec670cd45a0f1116eed6bf2e6923946cc233f19a6f9d003de889fae05b800de042dfa196f7354533670d6aa5d28bfd1e1676b4ec0e5edcb27ac24916f5139b32cac9ca7a9cbf75151fd60d4a124fd1e79932c98a595338dddb21a4a3a5136ec59af3f9af3611dd1ee21d6bcb1d02e79f7d1b5bac400245dfa3aa34e14809afe43467f2f75a45e2575739d227527bcb8dcc5d476e1f4fba3445f85a5f12c42401fa7903a4d3520f851cbf2dcb8a385373508e5a28e8e09ea093c3a2123749670114e79f7639833cb5d9ab62f2442ef6efd65224719b5f3bbba0f89bac5c495dad5b10cbd153d2399c8e4e23ab57e9bae552cef07e3d473c45a521a22212099ad27f3f56ccc205b9039bac39ec424da49b8bac64c16fa842726db92c40e19c5446c86c3bbdcc504c47c17d6d79c2870d1b070b22823d48537baab70812cac032b4bb9aa39e5815b42e3d664cab8fe5c376774bc6be1cfa121f089accb5bbb56a72b2ea57515ac54ab3427a8d86264a6c3c5ee0166bc37e4f4277a63a1ea5d5f43f496426b13b90eb61d51b5538d04e8d62f6ac60f3f37f8379f90f8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90311);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/29");

  script_cve_id("CVE-2016-1350");
  script_osvdb_id(136248);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco IOS XE SIP Memory Leak DoS (CSCuj23293)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"TThe remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) gateway
implementation due to improper handling of malformed SIP messages. An
unauthenticated, remote attacker can exploit this, via crafted SIP
messages, to cause memory leakage, resulting in an eventual reload of
the affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc3f527");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCuj23293");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

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

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag     = 0;
override = 0;

affected = make_list(
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2S",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.11.0S"
);

flag = 0;
foreach badver (affected)
{
  if (badver == version)
  {
    flag = 1;
    break;
  }
}

# Configuration check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = " CCSIP_(UDP|TCP)_SOCKET(\r?\n|$)";
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_processes_include_sip","show processes | include SIP ");
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

if (flag)
{
    order  = make_list('Cisco bug ID', 'Installed release');
    report = make_array(
      order[0], "CSCuj23293",
      order[1], version
    );
    
    if (report_verbosity > 0)
      report = report_items_str(report_items:report, ordered_fields:order) + cisco_caveat(override);
    else # Cisco Caveat is always reported
      report = cisco_caveat(override);
    security_hole(port:0, extra:report);
    exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
