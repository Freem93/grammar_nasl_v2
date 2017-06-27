# This script was created by Jason Lidow <jason@brandx.net>
# The vulnerability was originally discovered by ts@securityoffice.net 

include("compat.inc");

if(description)
{
        script_id(11151);
        script_bugtraq_id(5803);
	script_osvdb_id(5371);
	script_cve_id("CVE-2002-1521");
        script_version("$Revision: 1.17 $");
        script_name(english:"Webserver 4D Plaintext Password Storage");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its Server response header, the remote web server is
Webserver 4D 3.6 or lower. Such versions store all usernames and
passwords in plaintext in the file 'Ws4d.4DD' in the application's
installation directory. A local attacker can exploit this flaw to gain
unauthorized privileges on this host."
  );
  # https://web.archive.org/web/20041213161024/http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f98ab628"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for an update."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/10/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/09");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
        script_summary(english:"Checks for Webserver 4D");

        script_category(ACT_GATHER_INFO);

        script_copyright(english:"This script is Copyright (C) 2002-2016 Jason Lidow <jason@brandx.net>");
        script_family(english:"CGI abuses");
        script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
        script_require_ports("Services/www", 80);
        exit(0);
}


include("http_func.inc");
port = get_http_port(default:80);


banner = get_http_banner(port:port);


poprocks = egrep(pattern:"^Server.*", string: banner);
if(banner)
{
        if("Web_Server_4D" >< banner) 
	{
                yo = string("\nThe following banner was received : ", poprocks, "\n");

                security_note(port:port, extra:yo);
 	}
}
