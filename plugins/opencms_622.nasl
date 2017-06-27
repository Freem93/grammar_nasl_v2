#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22093);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2006-3933", "CVE-2006-3934", "CVE-2006-3935", "CVE-2006-3936");
  script_bugtraq_id(19174);
  script_osvdb_id(27551, 27552, 27553, 27554);

  script_name(english:"OpenCms < 6.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of OpenCms");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running OpenCms, a Java-based content management
system.

According to its banner, the version of OpenCms installed on the
remote host reportedly allows authenticated users to upload OpenCms
modules and database import/export files, download arbitrary files,
send messages to all users, and launch cross-site scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jul/615" );
  script_set_attribute(attribute:"see_also", value:"http://mail.opencms.org/pipermail/opencms-dev/2006q3/025016.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenCms version 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Only run the plugin if we're being paranoid to avoid false-positives,
# which might arise because the software is open source.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Check the version.
#
# nb: you can sometimes get the version from the Server response header,
#     but that won't work if Tomcat is used in conjunction with a webserver.
w = http_send_recv3(method:"GET", item:"/opencms/opencms/system/login/", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

if ("<title>Welcome to OpenCms" >< res)
{
  # Extract the version number.
  pat = "title>Welcome to OpenCms ([^<]+)</title";
  ver = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if the version is under 6.2.2.
  if (ver && ver =~ "^([0-5]\.|6\.([01]\.|2\.[01][^0-9]?))")
  {
    report = string(
      "Plugin output :\n",
      "\n",
      "The version of OpenCms on the remote host was determined to be ", ver, ".\n"
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
