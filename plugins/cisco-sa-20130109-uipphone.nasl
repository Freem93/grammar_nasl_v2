#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70096);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/07 17:35:30 $");

  script_cve_id("CVE-2012-5445");
  script_bugtraq_id(57090);
  script_osvdb_id(88395);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc83860");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130109-uipphone");

  script_name(english:"Cisco Unified IP Phones Privilege Escalation (cisco-sa-20130109-uipphone)");
  script_summary(english:"Checks IP phone software version");

  script_set_attribute(attribute:"synopsis", value:"The remote IP telephony device is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Unified IP Phone software running on the remote device has a local
privilege escalation vulnerability. Local attackers can exploit this
issue to gain elevated privileges. Successful exploits could result in
the complete compromise of the affected device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130109-uipphone
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d3bb16b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20130109-uipphone.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:ip_phone");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/CNU-OS", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# 'show version' on a Cisco IP Phone produced the following:
#
# CNU6-OS  9.0(2ES3.) 4.1(0.1) CP-7942G PSYL 0020-12(MIPS32)
#
# NOTE: It's unclear whether other versions follow this format.
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed   = '9.3(1)SR2 / 9.4(2)';
fixed_t = '9.3.1.2';
vuln_models = make_list(
'7975G',  '7971G-GE', '7970G',    '7965G',
'7962G',  '7961G',    '7961G-GE', '7945G',
'7942G',  '7941G',    '7941G-GE', '7931G',
'7911G',  '7906'
);

foreach m (vuln_models)
{
  if (
    m >< model &&
    ver_compare(ver:ver_t, fix:fixed_t, strict:FALSE) < 0
  )
  {
    report = NULL;
    if (report_verbosity > 0)
    {
      report =
        '\n  IP Phone model    : ' + m +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fixed + '\n';
    }
    security_warning(port:0, extra:report);
    exit(0);
  }
}
audit(AUDIT_INST_VER_NOT_VULN, 'Cisco Unified IP Phone', ver);
