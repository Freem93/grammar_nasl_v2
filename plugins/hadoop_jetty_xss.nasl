#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55975);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_cve_id("CVE-2009-1524");
  script_bugtraq_id(34800);
  script_osvdb_id(54187);

  script_name(english:"Apache Hadoop Jetty XSS");
  script_summary(english:"Attempts a reflected XSS");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a cross-site scripting vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache Hadoop running on the remote host has a cross-
site scripting vulnerability.  This is due to a bug in Jetty, the
underlying web server.  When Jetty displays a directory listing,
arbitrary text can be inserted into the page.  This affects all
Hadoop components that use the Jetty web server.

A remote attacker could exploit this by tricking a user into making a
maliciously crafted request, resulting in the execution of arbitrary
script code.

It is likely this version of Hadoop has other security vulnerabilities,
though Nessus did not check for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/HADOOP-6882");
  script_set_attribute(
    attribute:"see_also",
    value:"http://hadoop.apache.org/common/docs/r0.20.203.0/releasenotes.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Hadoop 0.20.203.0 or a later, stable version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:hadoop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("hadoop_mapreduce_jobtracker_web_detect.nasl", "hadoop_mapreduce_tasktracker_web_detect.nasl", "hdfs_namenode_web_detect.nasl", "hdfs_datanode_web_detect.nasl");
  script_require_ports("www/hadoop_mapreduce_jobtracker", "www/hadoop_mapreduce_tasktracker", "www/hdfs_namenode", "www/hdfs_datanode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

global_var xss, page;
xss = '<script>alert(/' + SCRIPT_NAME + '/)</script>';
page = '/logs/;' + xss;

# returns the PoC URL if it worked, NULL otherwise
function test_xss(dir, port)
{
  local_var url, expected_output, res;
  url = dir + page;

  expected_output = '<TITLE>Directory: ' + url + '</TITLE>';
  res = http_send_recv3(method:'GET', item:url, port:port);

  if (res && expected_output >< res[2])
    return url;
  else
    return NULL;
}

installs = 0;
urls = make_list();
port = get_http_port(default:50030);

components = make_list(
  'hadoop_mapreduce_jobtracker',
  'hadoop_mapreduce_tasktracker',
  'hdfs_namenode',
  'hdfs_datanode'
);


# see if a Hadoop web component was detected on this port
foreach component (components)
{
  # we only expect to see one dir per component, but we'll call
  # this function anyway to ensure we don't fork
  dirs = get_dirs_from_kb(appname:component, port:port);

  foreach dir (dirs)
  {
    installs++;
    url = test_xss(dir:dir, port:port);
    if (!isnull(url))
      urls = make_list(urls, url);
  }
}

if (!installs)
  exit(0, 'No Hadoop services were detected on port ' + port + '.');
if (max_index(urls) == 0)
  exit(0, 'No vulnerable Hadoop services were detected on port ' + port +'.');

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report = get_vuln_report(items:urls, port:port);
  security_warning(port:port, extra:report);
}
else security_warning(port);

