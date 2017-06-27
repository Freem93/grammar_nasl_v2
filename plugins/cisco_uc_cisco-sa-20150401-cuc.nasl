#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82702);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id(
    "CVE-2015-0612",
    "CVE-2015-0613",
    "CVE-2015-0614",
    "CVE-2015-0615",
    "CVE-2015-0616"
  );
  script_bugtraq_id(73476);
  script_osvdb_id(
    120179,
    120180,
    120181,
    120182,
    120183
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh25062");
  script_xref(name:"IAVA", value:"2015-A-0070");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul20444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul26267");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul28089");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul69819");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150401-cuc");

  script_name(english:"Cisco Unity Connection Multiple Remote DoS (cisco-sa-20150401-cuc)");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco Unity Connection installed on the remote host is
affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unity Connection installed on the remote host is
8.5 prior to 8.5(1)SU7 / 8.6 prior to 8.6(2a)SU4 / 9.x prior to
9.1(2)SU2 / 10.x prior to 10.0(1)SU1. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    Connection Conversation Manager (CuCsMgr) due to
    incorrect processing of specific UDP packets. An
    unauthenticated, remote attacker can exploit this issue
    by sending a specific UDP packet to the configured SIP
    trunk, resulting in the closure of the SIP port and
    the inability to process any further calls.
    (CVE-2015-0612)

  - A denial of service vulnerability exists in the
    Connection Conversation Manager (CuCsMgr) due to
    incorrect processing of SIP INVITE messages. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted SIP INVITE messages, to trigger a core
    dump of the CuCsMgr process. (CVE-2015-0613)

  - A denial of service vulnerability exists in the
    Connection Conversation Manager (CuCsMgr) due to
    incorrect processing of SIP INVITE messages. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted SIP INVITE messages, to trigger a core
    dump of the CuCsMgr process. (CVE-2015-0614)

  - A denial of service vulnerability exists in the SIP call
    handling code due to a failure to release allocated
    resources under specific connection scenarios. An
    unauthenticated, remote attacker can exploit this issue
    by abnormally terminating a SIP session, resulting in
    the consumption of all available SIP ports thus
    preventing further connections. (CVE-2015-0615)

  - A denial of service vulnerability exists in the
    Connection Conversation Manager (CuCsMgr) due to
    improper handling of incorrectly terminated SIP
    conversations. An unauthenticated, remote attacker can
    exploit this issue by abnormally terminating a SIP
    connection, triggering a core dump of the CuCsMgr
    process. (CVE-2015-0616)

Note that Cisco bug ID CSCuh25062 (CVE-2015-0612) does not affect the
10.0.x branch.

Further note that Cisco bug ID CSCuh25062 (CVE-2015-0612) is corrected
in version 8.5(1)SU6 for the 8.5.x branch. However, version 8.5(1)SU6
is still affected by the other vulnerabilities.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150401-cuc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96da7b7e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37806");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37807");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37834");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37808");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37809");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unity Connection 8.5(1)SU7 / 8.6(2a)SU4 / 9.1(2)SU2 /
10.0(1)SU1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("Host/Cisco/Unity_Connection/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/Unity_Connection/Version");

# version char '-' converted to '.' in ssh_get_info.nasl
if (version =~ "^8\.5(\.|$)")         fix = "8.5.1.17900";
else if (version =~ "^8\.6(\.|$)")    fix = "8.6.2.24900";
else if (version =~ "^9\.[01](\.|$)") fix = "9.1.2.12900";
else if (version =~ "^10\.0(\.|$)")    fix = "10.0.1.11900";
else                                  fix = "8.5.1.17900";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco Unity Connection", version);
