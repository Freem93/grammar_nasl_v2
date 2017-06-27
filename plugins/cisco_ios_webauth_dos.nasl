#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61492);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2012-1338");
  script_bugtraq_id(54834);
  script_osvdb_id(84506);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts88664");

  script_name(english:"Cisco IOS Web Authentication DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS installed on the remote host is affected by a
denial of service vulnerability due to an error while parsing local
web authentication. A remote attacker, by entering an extremely rapid
input of credentials, can exploit this to crash the switch, forcing a
reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=26615");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCts88664");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCts88664.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/Cisco/IOS/Model");

if ("3750-E" >!< model && "3560-E" >!< model)
  audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (version =="15.0(0.0.85)SE1") flag++;
if (version =="15.0(1)EW") flag++;
if (version =="15.0(2)EW") flag++;
if (version =="15.0(3)EW") flag++;
if (version =="15.0(4)EW") flag++;
if (version =="15.0(5)EW") flag++;
if (version =="15.0(6)EW") flag++;
if (version =="15.0(7)EW") flag++;
if (version =="15.0(8)EW") flag++;
if (version =="15.0(1)SE") flag++;
if (version =="15.0(1)SE1") flag++;
if (version =="15.0(1)SE2") flag++;
if (version =="15.0(1)SE3") flag++;
if (version =="15.0(2)SE") flag++;
if (version =="15.0(2)SE1") flag++;
if (version =="15.0(2)SE2") flag++;
if (version =="15.0(2)SG") flag++;
if (version =="15.0(2)SG1") flag++;
if (version =="15.0(2)SG2") flag++;
if (version =="15.0(2)SG3") flag++;
if (version =="15.0(2)SG4") flag++;
if (version =="15.0(2)SG5") flag++;
if (version =="15.0(2)SG6") flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Cisco bug ID      : CSCts88664' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
