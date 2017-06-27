#TRUSTED 0131ac4029eb5f4772cfdf7c1bed1bba963a308f701d4f41089e75d8782dd58d8826bbda8cff922f9d601b573e8e1c700907aa5b92fcff5c0483c7d407c768f43902cffe6b62f9f84a9cbee1a12a15646b45064630a0f2e08b3283d86dd147a98618a2b0582c7c680c54b1892ef907929ab0552e3a55e2f128be8f63e976d1c9262c250ae9a2677c9ef25fecbc9cf1defc959ac4ae3ba67c70703a68bb293959bbc9952ab4ff6b42b2c1dad8c249e92b9c8ae3c1db6ab7f3a4f0078c851b5676b16c06ddc72efcb43d4bb45e6b034800b51f104dafbd3a9b2e7b96e721d148555b4d13b26085a22b3237ce05faf87141db2a191f2402f19a60b5838233f868992d979c0d482e26cd334b4b044b1d7dc86577989b0607ba0cfce7364f1f03eb10b10e55544e522467cee7d3729aeb4950912dc960ee636d3b2973bb607b144d00c34e23d3c06d0ab564f5c64df35eb1e79fddae871dd03edfe13e88640597413cec556e927115b7c1a0aa6196ff0d8e7462c0097655099b9b321a527e8c4e050c197f0c279a56c6783d4cebcb28f50b497137e165ca39a710d77b0eea18dc4e124f0c6485fe2b2536b39c7d62cb3cea2018004cd1f85cc7696249e66684b2ca24bf03191a0acc91513e259d81680657875deb3d89fa8c10b6031a03b73aab9a42d828e0630c3d60e7d9fbd469d05a4dbadba0b100b47971cca3ab42ec08db2785
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78036);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3360");
  script_bugtraq_id(70141);
  script_osvdb_id(112043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul46586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-sip");

  script_name(english:"Cisco IOS XE Software SIP DoS (cisco-sa-20140924-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a vulnerability in the
Session Initiation Protocol (SIP) implementation due to improper
handling of SIP messages. A remote attacker can exploit this issue by
sending specially crafted SIP messages to cause the device to reload.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61c56b95");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35611");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35259");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul46586");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCul46586";
fixed_ver = NULL;

if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^2\.6\." ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-5]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[0-2]S$" ||
  ver =~ "^3\.10.(0a|[0-3])S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# SIP check
# nb SIP can listen on TCP or UDP
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # SIP UDP listening check
  # Example:
  # 17     0.0.0.0             0 --any--          5060   0   0    11   0
  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:\S+\s+){4}5060\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # SIP TCP listening check
    # Example:
    # 7F1277405E20  0.0.0.0.5061               *.*                         LISTEN
    # 7F127BBE20D8  0.0.0.0.5060               *.*                         LISTEN
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^\S+\s+\S+(506[01])\s+", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because SIP is not listening on TCP or UDP.");
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
