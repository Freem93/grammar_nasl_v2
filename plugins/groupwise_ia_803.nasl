#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62284);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/14 15:43:28 $");

  script_cve_id("CVE-2011-3827", "CVE-2012-0417", "CVE-2012-0419");
  script_bugtraq_id(55574, 55648, 55731);
  script_osvdb_id(85724, 85801, 85803, 87293);
  script_xref(name:"EDB-ID", value:"22707");

  script_name(english:"Novell GroupWise Internet Agent 8.x < 8.0.3 / 12.x < 12.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks GWIA version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is susceptible to a
denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Internet Agent running on the remote
host is 8.x earlier than 8.0.3 or 12.x earlier than 12.0.1. It
therefore is potentially affected by multiple vulnerabilities :

  - A denial of service vulnerability exists due to the way
    that the application parses date information within a
    received iCalendar message. A remote attacker could
    exploit this flaw to crash the affected service.
    (CVE-2011-3827)

  - An unspecified integer overflow vulnerability exists
    that could lead to code execution. (CVE-2012-0417)

  - An arbitrary file retrieval vulnerability exists due to
    a failure to properly filter certain crafted directory
    traversal sequences in the HTTP interface.
    (CVE-2012-0419)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-30/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010767");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010770");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010772");
  script_set_attribute(attribute:"solution", value:"Update GWIA to version 8.0.3, 12.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "groupwise_ia_detect.nasl");
  script_require_keys("SMB/GWIA/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit("SMB/GWIA/Version");
path = get_kb_item_or_exit("SMB/GWIA/Path");

# Unless we're paranoid, make sure the service is running.
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit("SMB/svc/GWIA");
  if (status != SERVICE_ACTIVE)
    exit(0, "The GroupWise Internet Agent service is installed but not active.");
}

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.3.21395') == -1)
  fixed_version = '8.0.3.21395';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.1.13731') == -1)
  fixed_version = '12.0.1.13731';

# Check the version number.
if (fixed_version)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'GroupWise Internet Agent', version, path);
