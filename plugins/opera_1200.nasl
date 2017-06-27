#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(59555);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2012-3555",
    "CVE-2012-3556",
    "CVE-2012-3557",
    "CVE-2012-3558",
    "CVE-2012-3560"
  );
  script_bugtraq_id(54011, 73573);
  script_osvdb_id(82951, 82952, 82953, 82954, 82955);

  script_name(english:"Opera < 12 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is prior to 12.00.
It is, therefore, affected by multiple vulnerabilities :

  - An error exists that can allow the address bar to
    display incorrect locations due to certain combinations
    of navigation, reloads and redirects, which can aid in
    phishing attacks. (1018)

  - An error in JSON handling can allow cross-site
    scripting attacks. (1019)

  - An error exists related to handling double-click
    actions and new windows that can be used in cross-site
    scripting attacks. (1020)

  - An error exists in the handling of window focus that
    can allow keystrokes to be associated with non-visible
    windows. (1021)

  - An error in the handling of page loading can allow a
    malicious page to prevent the loading while showing an
    incorrect URL in the address bar. (1022)");
    
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1018/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1019/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1020/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1021/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1022/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1200");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

fixed_version = "12.0.1467.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.00")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.00";

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
