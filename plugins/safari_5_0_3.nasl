#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50654);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id(
    "CVE-2010-1812",
    "CVE-2010-1813",
    "CVE-2010-1814",
    "CVE-2010-1815",
    "CVE-2010-1822",
    "CVE-2010-3116",
    "CVE-2010-3257",
    "CVE-2010-3259",
    "CVE-2010-3803",
    "CVE-2010-3804",
    "CVE-2010-3805",
    "CVE-2010-3808",
    "CVE-2010-3809",
    "CVE-2010-3810",
    "CVE-2010-3811",
    "CVE-2010-3812",
    "CVE-2010-3813",
    "CVE-2010-3816",
    "CVE-2010-3817",
    "CVE-2010-3818",
    "CVE-2010-3819",
    "CVE-2010-3820",
    "CVE-2010-3821",
    "CVE-2010-3822",
    "CVE-2010-3823",
    "CVE-2010-3824",
    "CVE-2010-3826"
  );
  script_bugtraq_id(
    43079,
    43081,
    43083,
    44200,
    44206,
    44950,
    44952,
    44953,
    44954,
    44955,
    44956,
    44957,
    44958,
    44959,
    44960,
    44961,
    44962,
    44963,
    44964,
    44965,
    44967,
    44969,
    44970,
    44971
  );
  script_osvdb_id(
    66748,
    67460,
    67461,
    67862,
    67863,
    67930,
    67932,
    67933,
    68365,
    69426,
    69427,
    69430,
    69432,
    69433,
    69434,
    69435,
    69436,
    69437,
    69438,
    69439,
    69440,
    69442,
    69443,
    69444,
    89663
  );

  script_name(english:"Safari < 5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.0.3.  As such, it is potentially affected by numerous issues in
its WebKit component that could allow arbitrary code execution, session
tracking, address bar spoofing, and other sorts of attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4455");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Nov/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

if (ver_compare(ver:version, fix:"5.33.19.4") == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 5.0.3 (7533.19.4)\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
