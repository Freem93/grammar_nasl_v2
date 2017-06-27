#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73457);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/12 00:42:55 $");

  script_cve_id("CVE-2014-2141");
  script_bugtraq_id(66666);
  script_osvdb_id(105485);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug97416");
  script_xref(name:"IAVB", value:"2014-B-0038");

  script_name(english:"Cisco ONS 15454 Controller Card DoS (CSCug97416)");
  script_summary(english:"Checks the ONS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in Cisco ONS 15454 Controller Cards that could
allow an authenticated, remote attacker to cause the control card to
reset, resulting in a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2141
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d263c67");
  script_set_attribute(attribute:"see_also",value:"https://tools.cisco.com/bugsearch/bug/CSCug97416");
  script_set_attribute(attribute:"solution", value:
"Contact normal Cisco support channels to upgrade to a software version
that includes fixes for this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ons");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ons_detect.nasl");
  script_require_keys("Cisco/ONS/Device", "Cisco/ONS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device_name = "Cisco ONS 15454";
device = get_kb_item_or_exit("Cisco/ONS/Device");
version = get_kb_item_or_exit("Cisco/ONS/Version");

if (device !~ "^15454") audit(AUDIT_HOST_NOT, device_name);

match = eregmatch(pattern: "^(\d+(?:\.\d+)*)-", string:version);
if (isnull(match)) exit(1, "Error parsing version string.");

# Format version string.
match = eregmatch(pattern:"^(\d+)\.(\d)(\d)(\d)?$", string:match[1]);
if (isnull(match)) exit(1, "Error parsing version string.");
else if (max_index(match) < 4) audit(AUDIT_VER_NOT_GRANULAR, device_name, version);

version_formatted = join(make_list(string(int(match[1])), match[2], match[3]), sep:'.');
if (match[4]) version_formatted += '.' + match[4];

# Check version.
flag = 0;
if (version_formatted =~ "^8\.0\.0(\.|$)") flag++;
else if (version_formatted =~ "^8\.5\.[0-3](\.|$)") flag++;
else if (version_formatted =~ "^9\.[013468]\.0(\.|$)") flag++;
else if (version_formatted =~ "^9\.2\.[0-2](\.|$)") flag++;

if (flag)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version_formatted + ' (' + version + ')' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, device_name, version);
