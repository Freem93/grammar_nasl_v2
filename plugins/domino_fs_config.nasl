#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10058);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2000-0021");
 script_bugtraq_id(881);
 script_osvdb_id(50);

 script_name(english:"IBM Lotus Domino HTTP Server Filesystem Setup Disclosure");
 script_summary(english:"obtains absolute path to cgi-bin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue.");
 script_set_attribute(attribute:"description", value:
"It is possible to get the absolute path leading to the remote /cgi-bin
directory by requesting a bogus cgi.  This issue can be used to obtain
OS and installation details.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Dec/257");
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/21");
 script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl","www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

  bogus = "just_a_test_ignore";
  dir = "/cgi-bin";
  url = strcat(dir, "/", bogus);
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);
s = strcat(r[0], r[1], '\r\n', r[2]);

  line = egrep(pattern:url, string:s);
  if (line && "http://" >!< line && "https://" >!< line)
  {
    path = ereg_replace(pattern:string('.* ([^ ]+)/', bogus, ".*"), replace:"\1", string:line);
    if (path) path = ereg_replace(pattern:"^'(.+)", replace:"\1", string:path);   
    if (path && ereg(pattern:strcat('^[^<>"]+', dir), string:path))
    {
      report = string(
        "\n",
        "The physical path discovered is :\n",
        "\n",
        "  ", path
      );
      security_warning(port:port, extra:report);
    }
  }

