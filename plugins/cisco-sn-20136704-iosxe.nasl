#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71924);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/13 19:28:08 $");

  script_cve_id("CVE-2013-6704");
  script_bugtraq_id(64062);
  script_osvdb_id(100520);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty42686");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh09324");

  script_name(english:"Cisco IOS XE Software TFTP DoS");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the flow manager code in Cisco IOS XE could allow a
remote, unauthenticated attacker to trigger a denial of service
condition resulting in a crash of the device by sending specially
generated TFTP UDP traffic. 

It should be noted that this plugin merely checks for an affected IOS XE
version and does not attempt to perform any additional validity checks."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6704
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c603643");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco Security Notice.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

report = '';

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 15.0(2)SG1 -> 3.2.1SG
if (version == '3.2.1SG')
{
  report =
  '\n  Cisco Bug ID        : CSCty42686' +
  '\n    Installed release : ' + version + '\n';
}

image = get_kb_item("Host/Cisco/IOS-XE/Image");
if (!isnull(image) && image != '')
{
  image = tolower(image);
  if (
    'cat4500e-universalk9' >< image ||
    'cat3k_caa-universalk9' >< image ||
    'ct5760-ipservicesk9' >< image
  )
  {
    # 15.0(1)EX2 -> 3.2.2SE
    if (version == '3.2.2SE')
    {
      report =
      '\n  Cisco Bug ID        : CSCuh09324' +
      '\n    Installed release : ' + version + '\n';
    }
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
