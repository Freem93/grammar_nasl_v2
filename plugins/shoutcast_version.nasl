#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10717);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2001-1304");
  script_osvdb_id(595);

  script_name(english:"SHOUTcast Server User-Agent / Host Header DoS");
  script_summary(english:"Checks for User-Agent / Host header denial of service vulnerability in SHOUTcast Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is prone to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SHOUTcast Server, a streaming audio server
from Nullsoft. 

According to its banner, the installed version of SHOUTcast server will
reportedly crash when it receives several HTTP requests with overly long
User-Agent and/or Host request headers.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Aug/57");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:shoutcast_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8000);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8000);

w = http_send_recv3(method:"GET", item:"/stream/0", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if the version is 1.8.2 or lower.
    if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\..*|1\.([0-7]\..*|8\.[0-2]))[^0-9]", string:res)) {
      security_warning(port);
      exit(0);
    }
