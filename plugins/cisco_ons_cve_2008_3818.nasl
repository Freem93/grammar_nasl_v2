#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69059);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2008-3818");
  script_bugtraq_id(33261);
  script_osvdb_id(51392);

  script_name(english:"Cisco ONS Products Remote DoS");
  script_summary(english:"Checks software version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ONS device is affected by a denial of service
vulnerability that can be triggered by a specially crafted TCP stream. 
Successful exploitation will cause a reload of the device's control
card."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20090114-ons.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the device software to the appropriate version per the vendor's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ons");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ons_detect.nasl");
  script_require_keys("Cisco/ONS/Device", "Cisco/ONS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device = get_kb_item_or_exit("Cisco/ONS/Device");
version = get_kb_item_or_exit("Cisco/ONS/Version");

report = '';

if (
  device =~ "^15310" || device =~ "^15327" ||
  device =~ "^15454" || device =~ "^15600"
)
{
  item = eregmatch(pattern: "^([0-9.]+)-", string:version);
  if (isnull(item)) exit(1, "Error parsing version string.");

  # nb: strip leading zeros
  int_version = eregmatch(pattern:"^0*([1-9][0-9]*)\.([0-9])([0-9])([0-9])?$", string:item[1]);

  if (max_index(int_version) < 4 || isnull(int_version)) exit(1, "Error parsing version string.");

  formatted_ver = join(make_list(int_version[1], int_version[2], int_version[3]), sep:'.');
  if (max_index(int_version) > 4) formatted_ver += "." + int_version[4];

  fix = '';

  if (formatted_ver =~ "^7\.0\.[245]$") fix = '7.0.7';
  else if (formatted_ver =~ "^7\.2\.[02]$") fix = '7.2.3';
  else if (formatted_ver =~ "^8\.(0\.|5\.[012]$)") fix = "8.5.3";

  if (fix != '')
  {
    report = '\n  Installed version : ' + formatted_ver + ' (' + version + ')' +
             '\n  Fixed version     : ' + fix + '\n';
  }
}
else
  exit(0, "The remote Cisco ONS Device is not affected.");

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ONS", version);
