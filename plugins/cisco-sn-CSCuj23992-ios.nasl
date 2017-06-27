#TRUSTED 430bb0ea51a9a917fe3469358b89208993bf4d48358157331e394d0e380f62690671a6e8eaf1ecf9d92e8e372941addda8a3576e81317a87ab0558c561c7b3b96f46ed9f6bf624e2ac4871990901593f467be51d54a116f80700f1857e3be1581381514d60ff3e76b6542c400312e393af93715f4e1c6435e4e99e513c74f9d5820653fe435f246cb5fd685ba6926903c2267c5f612a48042df3fb2a01ad8b6c55238a2504466b0be9b9d72aa344b8acfd2635ec5739d49cd1460cb761470f824e49108b6250107423af7fc1b66ff54d6ef1ef044304d7fa9e877090b3db0191eec207f350304dc7562b75f7118afdefd288eb0ac46510f0f005fae35c30d1a58c28441bf7e36ffb2567d22131886b7dfd02f4405d6b29f29c9b199678d5bbc0bb92f5c3c9dec455e35ef6b888bae69e1cbaa37468f09c8c3079548a16498fbbcfe2abbfbda87fd28bc921aa48cccf634538364b2e5c85b2abab5f28ae8b4e3da518bf65f82333712a96928f6527a27861d16c07716b4e44faad359a7cbcb31dff0b1dd3bda845e17062efd27d93c94a4a43674fb4b6639ac60de655e2241e1eaf172c080d88cde325e8b4d856b74bd92a03d20b96e07f5f5998506207e04686740df875fe06546f67eb49e7ad81370782cc57223f0a371cd9e4bdfc94f6784be6637ff8fe2ed2d90f703186d83b33c70b1392dfd64f00452b7acc5d99fe6177
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78690);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6706");
  script_bugtraq_id(63979);
  script_osvdb_id(100394);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23992");

  script_name(english:"Cisco IOS IP Header Sanity Check DoS (CSCuj23992)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability in the Cisco Express
Forwarding processing module.

The issue is due to improper processing of MPLS packets. When certain
additional features are configured, an attacker can exploit this
vulnerability by sending MPLS packets to traverse and exit an affected
device as IP packets. This may cause the device to reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31950");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6706
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa061ffd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj23992.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# this advisory only addresses CISCO ASR 1000 series
model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
if (model !~ '^ASR 10[0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

if (version == '15.3(2)S1') flag++;
else if (version == '15.3(2)S') flag++;
else if (version == '15.0(1)S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:"ip cef accounting", string:buf) &&
        preg(multiline:TRUE, pattern:"tcp adjust-mss", string:buf)
      ) flag = 1;
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuj23992' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
