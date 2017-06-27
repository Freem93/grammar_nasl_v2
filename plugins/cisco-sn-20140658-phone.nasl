#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72725);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2014-0658");
  script_bugtraq_id(64770);
  script_osvdb_id(101913);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul24898");

  script_name(english:"Cisco 9900 Series IP Phone Crafted Header Unregister Vulnerability");
  script_summary(english:"Checks IP phone software version");

  script_set_attribute(attribute:"synopsis", value:"The remote IP telephony device is missing a vendor-supplied patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of the Cisco
Unified IP Phone software running on the remote device does not properly
process SIP headers.  By sending a specially crafted SIP header to the
device, a remote attacker may be able to cause the phone to unregister,
resulting in a denial of service condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0658
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f411bf93");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in Cisco Security Notice.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:ip_phone");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/CNU-OS", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# 'show version' on a Cisco IP Phone produced the following:
#
# CNU6-OS  9.0(2ES3.) 4.1(0.1) CP-7942G PSYL 0020-12(MIPS32)
#
ver_str = get_kb_item_or_exit('Host/Cisco/CNU-OS');

arr = eregmatch(string:ver_str, pattern:'([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+)');
if (isnull(arr)) exit(1, 'Failed to parse Cisco Native Unix OS version string.');

ver   = arr[2];
model = arr[4];

# 9.0(2ES3) -> 9.0.2.3
arr = eregmatch(string:ver, pattern:'([0-9.]+)[^0-9]+([0-9]+)[^0-9]+([0-9]+)');
if (isnull(arr)) exit(1, 'Failed to get Cisco IP phone software version.');
ver_t = arr[1] + '.' + arr[2] + '.'+arr[3];

fixed   = '9.4(1)ES1';
fixed_t = '9.4.1.1';
vuln_models = make_list(
  9951, 9971,8961, 8945, 8941
);

model_found = FALSE;

foreach m (vuln_models)
  if(m >< model) model_found = TRUE;

if (
  model_found &&
  ver_compare(ver:ver_t, fix:fixed_t, strict:FALSE) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  IP Phone model    : ' + m +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fixed + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}

if(!model_found) exit(0, "Cisco IP Phone Model " + model + " is not affected.");
audit(AUDIT_INST_VER_NOT_VULN, 'Cisco Unified IP Phone OS', ver);
