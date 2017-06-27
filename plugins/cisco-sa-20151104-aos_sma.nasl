#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86915);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6321");
  script_osvdb_id(129893);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus79777");
  script_xref(name:"IAVA", value:"2015-A-0282");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-aos");

  script_name(english:"Cisco Content Security Management Appliance TCP Flood DoS (CSCus79777)");
  script_summary(english:"Checks the SMA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Content Security
Management Appliance (SMA) running on the remote host is affected by a
denial of service vulnerability in the network stack of Cisco AsynOS
due to improper handling of TCP packets sent at a high rate. An
unauthenticated, remote attacker can exploit this to exhaust all
available memory, preventing any more TCP connections from being
accepted.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-aos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e38ff5dd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisory
cisco-sa-20151104-aos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/Version');

if (ver =~ "^[0-7]\." || ver =~ "^8\.0\.") # Prior to 8.1
  display_fix = '9.1.0-031';
else if (ver =~ "^8\.1\.")
  display_fix = '9.1.0-031';
else if (ver =~ "^8\.3\.")
  display_fix = '9.1.0-031';
else if (ver =~ "^8\.4\.")
  display_fix = '9.1.0-031';
else if (ver =~ "^9\.0\.")
  display_fix = '9.1.0-031';
else if (ver =~ "^9\.1\.1\.")
  display_fix = '9.1.1-005';
else if (ver =~ "^9\.1\.")
  display_fix = '9.1.0-031';
else if (ver =~ "^9\.5\.")
  display_fix = '9.5.0-025';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);
