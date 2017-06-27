#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62283);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/16 11:00:58 $");
 
  script_cve_id(
    "CVE-2012-0271",
    "CVE-2012-1766",
    "CVE-2012-1767",
    "CVE-2012-1768",
    "CVE-2012-1769",
    "CVE-2012-1770",
    "CVE-2012-1771",
    "CVE-2012-1772",
    "CVE-2012-1773",
    "CVE-2012-3106",
    "CVE-2012-3107",
    "CVE-2012-3108",
    "CVE-2012-3109",
    "CVE-2012-3110"
  );
  script_bugtraq_id(
    54497,
    54500,
    54504,
    54506,
    54511,
    54531,
    54536,
    54541,
    54543,
    54546,
    54548,
    54550,
    54554,
    55551
  );
  script_osvdb_id(
    83900,
    83901,
    83902,
    83903,
    83904,
    83905,
    83906,
    83907,
    83908,
    83909,
    83910,
    83911,
    83944,
    85426
  );

  script_name(english:"Novell GroupWise Internet Agent 8.x <= 8.0.2 HP3 / 12.x < 12.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks GWIA version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Internet Agent running on the remote
host is 8.x less than or equal to 8.0.2 HP3, or 12.x earlier than 
12.0.1.  As such, it is potentially affected by multiple 
vulnerabilities :

  - A heap-based buffer overflow vulnerability exists when
    parsing requests to the web-based admin interface with
    a specially crafted Content-Length header. 

  - Multiple vulnerabilities exist in the bundled Oracle 
    'Outside In' viewer technology.

By exploiting these flaws, a remote, unauthenticated attacker could 
execute arbitrary code on the remote host subject to the privileges of
the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010769");
  script_set_attribute(attribute:"solution", value:"Update GWIA to version 8.0.3 Hot Patch 1, 12.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-497");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:groupwise");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.2.16933') <= 0)
  fixed_version = '8.0.3.23395';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.1.13731') == -1)
  fixed_version = '12.0.1.13731';

# Check the version number.
if (fixed_version);
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
audit (AUDIT_INST_PATH_NOT_VULN, 'GroupWise Internet Agent', version, path);
