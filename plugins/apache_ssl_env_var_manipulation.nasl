#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31738);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-0555");
  script_bugtraq_id(28576);
  script_osvdb_id(43997);
  script_xref(name:"Secunia", value:"29644");

  script_name(english:"Apache-SSL ExpandCert() Function Certificate Handling Arbitrary Environment Variables Manipulation");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a memory disclosure / privilege
escalation attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache-SSL running on the
remote host is older than apache_1.3.41+ssl_1.59. Such versions fail
to properly sanitize certificate data before using it to populate
environment variables.  By sending a client certificate with special
characters for the subject, a remote attacker can overwrite certain
environment variables used by the web server, resulting in memory
disclosure or potential privilege escalation in a web application." );
 script_set_attribute(attribute:"see_also", value:"https://www.cynops.de/advisories/CVE-2008-0555.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache-ssl.org/advisory-cve-2008-0555.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Apr/19" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to apache_1.3.41+ssl_1.59 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20,287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/03");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache-ssl:apache-ssl");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Don't bother unless the service uses SSL.
encaps = get_kb_item("Transports/TCP/"+port);
if (
  isnull(encaps) || 
  encaps < ENCAPS_SSLv2 || encaps > ENCAPS_TLSv1
) exit(0);


# Check the version in the banner.
banner = get_backport_banner(banner:get_http_banner(port:port));
if (!banner) exit(0);

server = strstr(banner, "Server:");
server = server - strstr(server, '\r\n');
if (" Ben-SSL/" >< server)
{
  ver = NULL;

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/([0-9]+\.[0-9]+)";
  item = eregmatch(pattern:pat, string:server);
  if (!isnull(item)) ver = item[2];

  if (!isnull(ver) && ver =~ "^1\.([0-9]($|[^0-9])|([0-4][0-9]|5[0-8])($|[^0-9]))")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote Apache-SSL server uses the following Server response\n",
        "header :\n",
        "\n",
        "  ", server, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
