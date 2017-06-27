#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69916);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2012-4599");
  script_bugtraq_id(55088);
  script_osvdb_id(84891);
  script_xref(name:"IAVA", value:"2012-A-0140");
  script_xref(name:"MCAFEE-SB", value:"SB10029");

  script_name(english:"McAfee SmartFilter Administration < 4.2.1.01 Unauthenticated Access to JBOSS RMI (SB10029)");
  script_summary(english:"Checks version of McAfee SmartFilter Administration");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee SmartFilter Administration installed on the
remote Windows host is earlier than 4.2.1.01.  It is, therefore,
potentially affected by a code execution vulnerability.  The Remote
Method Invocation service can be used without authentication to deploy a
malicious .war file.  By exploiting this flaw, a remote, unauthenticated
attacker could execute arbitrary code subject to the privileges of the
user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10029");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-140/");
  script_set_attribute(attribute:"solution", value:"Upgrade to McAfee SmartFilter Administration 4.2.1.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:smartfilter_administration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_smartfilter_administration_installed.nasl");
  script_require_keys("SMB/McAfee SmartFilter Administration/Version", "SMB/McAfee SmartFilter Administration/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/McAfee SmartFilter Administration/Version");
path = get_kb_item_or_exit("SMB/McAfee SmartFilter Administration/Path");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed version is 4.2.1.1
if (
  ver[0] < 4 ||
  (ver[0] == 4 && ver[1] < 2) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 1) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] == 1 && (max_index(ver) == 3 || ver[3] < 1)))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.1.01\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'McAfee SmartFilter Administration', version, path);
