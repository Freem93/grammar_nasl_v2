#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74190);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2012-2041");
  script_bugtraq_id(53941);
  script_osvdb_id(82847);

  script_name(english:"Adobe ColdFusion HTTP Response Splitting (APSB12-15) (credentialed check)");
  script_summary(english:"Checks for hotfix file");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server is affected by an HTTP
response splitting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by an HTTP response splitting vulnerability.

The coldfusion.filter.ComponentFilter class does not properly sanitize
input used in the Location header of an HTTP response. A remote
attacker could exploit this by tricking a user into making a malicious
request, resulting in the injection of HTTP headers, modification of
the HTTP response body, or splitting the HTTP response into multiple
responses.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-15.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-15.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?8955b553");
  script_set_attribute(attribute:"solution", value:"Apply the hotfixes referenced in Adobe advisory APSB12-15.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('8.0.0', '8.0.1', '9.0.0', '9.0.1');
instances = get_coldfusion_instances(versions); # this exits if it fails

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "8.0.0")
    info = check_jar_hotfix(name, "00006", 4, make_list("00001", "00002", "00003", "00004", "00005", "1875", "1878", "70523", "71471", "73122", "77218"));
  else if (ver == "8.0.1")
    info = check_jar_hotfix(name, "00006", 5, make_list("00001", "00002", "00003", "00004", "00005", "1875", "1878", "71471", "73122", "77218"));
  else if (ver == "9.0.0")
    info = check_jar_hotfix(name, "00006", 2, make_list("00001", "00002", "00003", "00004", "00005"));
  else if (ver == "9.0.1")
    info = check_jar_hotfix(name, "00005", 3, make_list("00001","00002","00003", "00004"));

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0) exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
