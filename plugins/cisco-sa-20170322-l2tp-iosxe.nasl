#TRUSTED 6d34b25e00f740056a53eabc9bdaa36972659b9b24ef4df2cf29ab06e642d8025f7b02dae307ac4ad18495365bdaaa2cc2e238583aa1d9c4f237a0187e2514b623f96a5843cf75389d6185ff0b8061fe983917510103a7c5e6053e2126a59a284ab04f582aa470966defe793b4ae01ae42288df7a5c53cabb9c6f6150c71952063ce6520f49471934f39c635bfc8ced65a181ef6322f6361df318fb9d056bfc54a08354e6425ee85d7a066531aac59e0456ae5aa5decff13c34488b90b4ae90612efb744b0def3a21c9d93f91a066cab2bea8fa2c3aefbb507cdc3ca4d03a07188ac48341815889b2198fe8718edd492fe7ae38c185d47c1bf4d40499c0f03da921e0e3ff48f42666ddf9d87aba6a6563d56d34c76d925b616e65d8ec0e5c6442ec93c63a0bd7ef2fd1370bb56424c204c55746dd34481cd6517415997bbf44205e7cd8a976c94e692005962f1d169d971206d51bac7fa44825ce33cffd519ae6b6cbff1798febe7813448d64de25b2d6a5ff3fa8a94e81d3eb6e5b1a708fe21d6e06b02e697ba722b2507201bae46c1af0ead725656d19052c9ff8867a172baf3569220a9cfe8b853f722247c80b7d587d390a6c1921e4ebf287b42609bc6f3b4b9bfd56d1f5b68b5cc1d142ad754f0e9e09d796778c387639f6a2e8464c7f1b49015e0afd0d7ce79c69c0587475314600e4f74a5976b88fbea222c0e7e0b37
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99029);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3857");
  script_bugtraq_id(97010);
  script_osvdb_id(154191);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82078");
  script_xref(name:"IAVA", value:"2017-A-0083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-l2tp");

  script_name(english:"Cisco IOS XE L2TP Parsing DoS (cisco-sa-20170322-l2tp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in its Layer 2 Tunneling Protocol (L2TP) parsing
function due to insufficient validation of L2TP packets. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted L2TP packet, to cause the device to reload.

Note that this issue only affects devices if the L2TP feature is
enabled and the device is configured as an L2TP Version 2 (L2TPv2) or
L2TP Version 3 (L2TPv3) endpoint. By default, the L2TP feature is not
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fc7ea8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy82078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

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

if (
  ver == "3.1.0S" ||
  ver == "3.1.1S" ||
  ver == "3.1.2S" ||
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
  ver == "3.10.8aS" ||
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
  ver == "3.13.5aS" ||
  ver == "3.13.5S" ||
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
  ver == "3.15.4S" ||
  ver == "3.16.0cS" ||
  ver == "3.16.0S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.1S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.2bS" ||
  ver == "3.16.2S" ||
  ver == "3.17.0S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.1S" ||
  ver == "3.18.0aS" ||
  ver == "3.18.0S" ||
  ver == "3.2.1S" ||
  ver == "3.2.2S" ||
  ver == "3.3.0S" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.1S" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.2S" ||
  ver == "3.4.0aS" ||
  ver == "3.4.0S" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1S" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2S" ||
  ver == "3.4.3S" ||
  ver == "3.4.4S" ||
  ver == "3.4.5S" ||
  ver == "3.4.6S" ||
  ver == "3.5.0S" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1S" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2S" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3SQ" ||
  ver == "3.6.0S" ||
  ver == "3.6.1S" ||
  ver == "3.6.2S" ||
  ver == "3.7.0S" ||
  ver == "3.7.1S" ||
  ver == "3.7.2S" ||
  ver == "3.7.3S" ||
  ver == "3.7.4S" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.8.0S" ||
  ver == "3.8.1S" ||
  ver == "3.8.2S" ||
  ver == "3.9.0S" ||
  ver == "3.9.1S" ||
  ver == "3.9.2S" ||
  ver == "16.2.1"
)
{
  flag++;
}

cmds = make_list();
# Check for the presence of an L2TPv3 pseudowire configuration or an
# L2TP virtual private dialup network (VPDN) configuration
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show run | include vpdn|pseudowire|xconnect","show run | include vpdn|pseudowire|xconnect");
  if (check_cisco_result(buf))
  {
    if ( ("vpdn enable" >< buf) || ("pseudowire-class" >< buf) || ("xconnect " >< buf) )
    {
      cmds = make_list(cmds, "show run | include vpdn|pseudowire|xconnect");
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
    bug_id   : "CSCuy82078",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
