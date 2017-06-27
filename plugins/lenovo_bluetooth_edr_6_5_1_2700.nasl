#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65986);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2013-1361");
  script_bugtraq_id(57504);
  script_osvdb_id(89483);

  script_name(english:"Lenovo ThinkPad Bluetooth with Enhanced Data Rate Arbitrary DLL Injection Code Execution Vulnerability");
  script_summary(english:"Checks version of Lenovo ThinkPad Bluetooth with Enhanced Data Rate");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by an arbitrary DLL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Lenovo ThinkPad Bluetooth with
Enhanced Data Rate installed that uses fixed paths for including
DLL files that may not be trusted.  By tricking a user into opening a
file in a directory accessible by an attacker, it may be possible to
inject and execute code from arbitrary .dll files."
  );
  script_set_attribute(attribute:"see_also",value:"http://download.lenovo.com/ibmdl/pub/pc/pccbbs/mobiles/g4wb10ww.txt");
  script_set_attribute(attribute:"see_also",value:"http://technet.microsoft.com/en-us/security/msvr/msvr13-001");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Lenovo ThinkPad Bluetooth with Enhanced Data Rate version 6.5.1.2700
or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date",value:"2013/04/11");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:lenovo:thinkpad_bluetooth_with_enhanced_data_rate_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("lenovo_bluetooth_edr_installed.nasl");
  script_require_keys("SMB/Lenovo_BT_EDR/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("misc_func.inc");
include('smb_func.inc');

app = 'Lenovo ThinkPad Bluetooth with Enhanced Data Rate Software';
kb_base = "SMB/Lenovo_BT_EDR/";
port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "6.5.1.2700";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
