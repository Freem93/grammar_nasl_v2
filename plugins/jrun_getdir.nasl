#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10814);
  script_version ("$Revision: 1.33 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_cve_id("CVE-2001-1510");
  script_bugtraq_id(3592);
  script_osvdb_id(680);

  script_name(english:"Allaire JRun Encoded JSP Request Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Allaire JRun running on the remote host is affected by
an information disclosure vulnerability due to an issue in handling
malformed URLs. An unauthenticated, remote attacker can exploit this,
via a crafted request, to display a listing of files in arbitrary
directories, which may contain sensitive files.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/3689");
  script_set_attribute(attribute:"solution", value:
"Disable directory browsing in each of the applications and refer to
the referenced URL for further steps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:macromedia:jrun");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (thorough_tests)
  dirs = list_uniq(make_list("/images", "/html", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

dir_lists = get_kb_list('www/'+port+'/content/directory_index');
new_dirs = make_list();

foreach dir (dirs)
{
  foreach dir_list (dirs_list)
  {
    # Skip if the root dir contains a dir listing to avoid a FP situation
    if (dir >< dir_list) continue;
    else new_dirs = make_list(new_dirs, dir);
  }
}

foreach dir (new_dirs)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/%3f.jsp",
    exit_on_fail : TRUE
  );
  if ( ("Index of" >< res[2]) || ("[To Parent Directory]" >< res[2]) )
  {
    output = strstr(res[2], "Index of");
    if (empty_or_null(output))
      output = strstr(res[2], "[To Parent Directory");
    if (empty_or_null(output))
      output = res[2];

    security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_WARNING,
      request      : make_list(build_url(qs:dir + "/%3f.jsp", port:port)),
      output       : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
