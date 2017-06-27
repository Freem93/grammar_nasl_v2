#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10704);
  script_version ("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/12/30 22:07:39 $");

  script_cve_id("CVE-2001-0731");
  script_bugtraq_id(3009);
  script_osvdb_id(582);
  script_xref(name:"OWASP", value:"OWASP-CM-004");
  script_xref(name:"EDB-ID", value:"21002");

  script_name(english:"Apache Multiviews Arbitrary Directory Listing");
  script_summary(english:"Attempts to find a directory listing.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Apache web server running on the remote host is affected by an
information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, by sending a crafted request, to display a
listing of a remote directory, even if a valid index file exists in
the directory.");
  # https://web.archive.org/web/20140222183713/http://httpd.apache.org/security/vulnerabilities_13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?616c9011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 1.3.22 or later. Alternatively, as a
workaround, disable Multiviews.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check for dir listing on index
dir_lists = get_kb_list('www/'+port+'/content/directory_index');

# Exit if we've already flagged the directory.
foreach dir_list (dir_lists)
{
  if ("/" >< dir_list)
    exit(0, "A directory listing has already been identified on the web server at "+build_url(qs:dir_list, port:port));
}

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/?M=A",
  exit_on_fail : TRUE
);

if (("Index of " >< res[2]) && ("Last modified" >< res[2]))
{
  output = strstr(res, "Index of");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port         : port,
    generic      : TRUE,
    severity     : SECURITY_WARNING,
    request      : make_list(build_url(qs:"/?M=A", port:port)),
    output       : output
  );
  exit(0);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, "Apache", port);
