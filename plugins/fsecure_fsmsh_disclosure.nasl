#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15931);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2004-1223");
 script_bugtraq_id(11869);
 script_osvdb_id(12289);
 script_xref(name:"Secunia", value:"13416");
 
 script_name(english:"F-Secure Policy Manager Path Disclosure");
 script_summary(english:"Checks for /fsms/fsmsh.dll");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an information
disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running F-Secure Policy Manager, a distributed
administration software allowing a system administrator to control
applications from a single web console. 

There is a flaw in the file '/fsms/fsmsh.dll' that discloses the
physical path this application is under.  An attacker could use this
information to mount further attacks.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/102");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:f-secure:policy_manager");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
url = '/fsms/fsmsh.dll?';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The server didn't respond");

if ("Commdir path" >< res[2])
{
  if (report_verbosity > 0)
  {
    report = string(
      "Nessus exploited this issue by requesting the following URL :\n\n",
      "  ", build_url(qs:url, port:port), "\n"
    );

    if (report_verbosity > 1)
      report += string("\nWhich yielded :\n\n", res[2], "\n");

    security_warning(port:port, extra:res[2]);
  }
  else security_warning(port);
}
