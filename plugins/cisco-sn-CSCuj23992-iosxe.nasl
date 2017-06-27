#TRUSTED 57256fdbe06780e6cddbda5a57c57850817ba77c5dd6ea419923e5f198472bad6a1296ede26d6d665be6101e007a4cd9a50d966c91d6d14a504af3909ff6251ce632969d15634cd5971fdc0ef0b443224c883508c780745bf0f9cab1e882bdf552063ab201af58831a97104cdf2161ddd09862f6e8847f8aacd7482578bf45e789d1f0bd661a354599028c611d8d57c9eec32b2633ff81ae4f5ed336be66acffc5d9af8c9510266de0881eae50b372943d019271cd85c20ddfbb7a8d95e16dee649ab7c5b38edac05f947b3a786001c5c1ad59affaecf278a8cbafd5e6bf9026dc65ad3a68832b3de2a053c9418ac811b25f3b829ac3717080a62243caf2913e63510814d6a01bbff05f561d89c47960a6ae22cac9fa67855f94c8c6c761ca588e8bf501cf22c0f0a29da3fb608896c207c0884468ab214055cdfe3f3295147ef7fe3011697131de30590fb59662a63b2a8473d2afc6790c30c5549617b0ecf0f04176c215692b5c965bec409cb2ff4be722c67b1d4e784e6413092591a3cdcab17b5909fc112e74281cb9b1446839c6f1861cc596307fb63d308b630caf30743ea133e7f8d43e5b58b75907beea0c72cc09ef2b9963e0b47b361b39e46389958b5e97342b20b4439fe00877e300eda1b5ca96822aac7f73ad58a052605a167d37d953dd3b59d474b2ec63de44595a80670a4863939843a81cda3387a0873698
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78691);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6706");
  script_bugtraq_id(63979);
  script_osvdb_id(100394);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23992");

  script_name(english:"Cisco IOS XE IP Header Sanity Check DoS (CSCuj23992)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# this advisory only addresses CISCO ASR 1000 series
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (model !~ '^ASR 10[0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

if (version == '3.9.0S') flag++;
else if (version == '3.9.1S') flag++;

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
