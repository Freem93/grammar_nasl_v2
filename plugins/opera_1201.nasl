#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61414);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2012-3561",
    "CVE-2012-4142",
    "CVE-2012-4143",
    "CVE-2012-4144",
    "CVE-2012-4145",
    "CVE-2012-4146"
  );
  script_bugtraq_id(53474, 54779, 54780, 54782, 54788, 55703);
  script_osvdb_id(81809, 84447, 84448, 84449, 84450, 84688);

  script_name(english:"Opera < 12.01 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
12.01 and is, therefore, reportedly affected by multiple issues :

  - An error exists in the handling of certain URLs that
    can lead to memory corruption and possible code
    execution. (1016)

  - Errors exist in the handling of DOM elements and
    certain HTML characters that can lead to cross-site
    scripting. (1025, 1026)

  - Download dialog boxes can be made small enough that
    users may not realize they are accepting a download
    and further, executing such a download. (1027)

  - An attacker could cause an application crash by tricking
    a user into connecting to a malicious site, as 
    demonstrated by the Lenovo 'Shop Now' page. 
    (CVE-2012-4146)");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1016/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1025/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1026/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1027/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1201");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Opera/Path");
version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "12.1.1532.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.01")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.01";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
