#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40984);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_name(english:"Browsable Web Directories");
  script_summary(english:"Display all browsable web directories.");

  script_set_attribute(attribute:"synopsis", value:
"Some directories on the remote web server are browsable.");
  script_set_attribute(attribute:"description", value:
"Multiple Nessus plugins identified directories on the web server
that are browsable.");
 # http://projects.webappsec.org/w/page/13246922/Directory%20Indexing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a35179e");
  script_set_attribute(attribute:"solution", value:
"Make sure that browsable directories do not leak confidential
informative or give access to sensitive resources. Additionally, use
access restrictions or disable directory indexing for any that do.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "apache_dir_listing.nasl", "jrun_dir_listing.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default:80, embedded: TRUE);

dirs = get_kb_list_or_exit('www/'+port+'/content/directory_index');
dirs = make_list(dirs);
report  = '';

foreach d (sort(dirs)) report = report + build_url(port:port,qs:d) + '\n';
if (report == '') exit(0, "No browsable directories were found on the webserver on port " + port);
report = '\nThe following directories are browsable :\n\n' + report;

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
exit(0);
