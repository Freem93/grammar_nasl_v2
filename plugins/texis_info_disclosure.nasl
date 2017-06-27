#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


# Date: Fri, 14 Mar 2003 14:39:36 -0800
# To: bugtraq@securityfocus.com
# Subject: @(#)Mordred Labs advisory - Texis sensitive information leak
# From: sir.mordred@hushmail.com
#
# This is NOT CVE-2002-0266/BID4035 !


if(description)
{
 script_id(11400);
 script_version ("$Revision: 1.19 $");

 script_bugtraq_id(7105);
 script_osvdb_id(4314);
 
 script_name(english:"Thunderstone Software Texis Crafted Request Information Disclosure");
 script_summary(english:"Checks for texis.exe");
 
 script_set_attribute(attribute:"synopsis",value:
"The remote web server contains a CGI script that is susceptible to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Texis can be abused to disclose potentially
sensitive information about the remote host, such as its internal IP
address and the path to various components (eg, cmd.exe)." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2003/Mar/206"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2003/Mar/247"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Contact Thunderstone tech support for a patch."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/03/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach d ( cgi_dirs() )
{
  url = string(d, "/texis.exe/?-dump");
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit (1, "The web server failed to respond.");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  if("COMPUTERNAME" >< res )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
