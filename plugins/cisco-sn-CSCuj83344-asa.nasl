#TRUSTED a9dd87f6b4415983647707c17367cf479c55ca76505bc06855de94344e861c85bb2e443a9b309ffbf12c8e2535b3f5730e93c03074707d4d0fcbb2135879cb52acbc57c7de2bf75dca7db10347ff45c1f8b906a46b092220e1912c3947f9e95fea206f4e5d9c38d06d7eba4dbc87d91105dab1f8e5d59f8807544364b37e70c02f9f38f28ee6e86b34684827c2ae3d637bbff13ed80dbe616d440fdb5100fb65580a5581d9aadc17c10a26d4e2d69dde67b8b597895af2ffb57d0b7a041ea34a12695573b54733b232f004f6c0f7ebaad0aa8a138cecfef731fd6fc337e4904ce5e0e95dfefb0b28505f7cc62318e36ec2b48a9d2e9dd1f5666bb1d070db437fb1107753ea8d53ce10d2879a5f4766f3097c3c98dad21b5c944f86e95680c27d7581e3665528beee333107a26ac11b6cf5b79473ac552566da3b79551743abc60d6a733cf4eef6e4f68417b61a1a1274b8ec078060b3dc05a1de49a1d33c6a2647aa1cec29aa91b44ac897489084dfe5b5e47fecfa9b918865300c30bc79d966f44a42602dbeb4cc692172fae8212641d736b64261128246734e0c610678ea7d736868958011f7da57350bbb29005d4c9ca0ef0b52d475212b0c0962fc0bbd7ffa838ab0f0ffdb32529f231b85749daff567b60e4ea3dd3a77ea815fb110785a0839b366c413b5cf6fda693d4864baa822eb676854596b305b7aec6d1ac5cb25
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77411);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6691");
  script_bugtraq_id(68517);
  script_osvdb_id(109049);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj83344");

  script_name(english:"Cisco ASA WebVPN CIFS Share Enumeration DoS (CSCuj83344)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability in the WebVPN CIFS
(Common Internet File System) access function due to missing bounds
checks on received responses when enumerating large amounts of shares
on a CIFS server. A remote, authenticated attacker can exploit this
issue by attempting to list the shares of a CIFS server with a large
amount of shares.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6691
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4711f07a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34921");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuj83344.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASA 5500-X series');

fixed_ver = NULL;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.8)"))
  fixed_ver = "8.4(7)8";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.2)"))
  fixed_ver = "9.0(4)2";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if CIFS is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s+nbns-server ", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because CIFS does not appear to be enabled.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
