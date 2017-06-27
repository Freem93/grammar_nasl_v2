#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62821);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2012-6461",
    "CVE-2012-6462",
    "CVE-2012-6463",
    "CVE-2012-6464",
    "CVE-2012-6465",
    "CVE-2012-6466",
    "CVE-2012-6467"
  );
  script_bugtraq_id(56407, 57120, 57121, 57132);
  script_osvdb_id(87099, 87100, 87101, 87102, 87103, 87234, 88924);

  script_name(english:"Opera < 12.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
12.10 and is, therefore, reportedly affected by the following
vulnerabilities : 

  - An error exists related to certificate revocation
    checking that can allow the application to indicate
    that a site is secure even though the check has not
    completed. (1029)

  - An error exists related to Cross-Origin Resource
    Sharing (CORS) handling that can allow specially
    crafted requests to aid in disclosing sensitive
    data. (1030)

  - An error exists related to data URIs that allows
    bypassing of the 'Same Origin Policy' and cross-site
    scripting attacks. (1031)

  - An error exists related to JavaScript and native
    objects that allows domains to override methods of
    other domains. This error can aid in cross-site
    scripting attacks. (1032)

  - An error exists related to SVG image handling that
    can result in arbitrary code execution. (1033)

  - An error exists related to the handling of shortcuts
    in inline elements that can cause the application to
    be redirected to malicious pages. This error can aid
    in phishing attacks. (1034)

  - An error exists related to the handling of 'WebP'
    images that can allow disclosure of memory contents.
    (1035)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1029/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1030/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1031/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1032/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1033/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1034/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1035/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/1210/");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/06");

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

fixed_version = "12.10.1652.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.10")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.10";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
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
