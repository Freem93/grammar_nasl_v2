#
# This script was written by Erik Stephens <erik@edgeos.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if(description)
{
  script_id(12198);
  script_version ("$Revision: 1.14 $");
  script_cve_id("CVE-2002-2276");
  script_bugtraq_id(6333);
  script_osvdb_id(4928);

  script_name(english:"Ultimate PHP Board add.php Direct Request Information Disclosure");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultimate PHP Board (UPB).  There is a flaw
in this version that could allow an attacker to view private message
board information."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/07");
 script_cvs_date("$Date: 2011/12/09 22:58:49 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english:"Checks for UPB");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Edgeos, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach d (list_uniq(make_list("/upb", "/board", cgi_dirs())))
{
  url = d + "/db/users.dat";
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" didn't respond.");
  if (egrep(pattern:"^Admin<~>", string:res[2]))
  {
    security_warning(port);
    exit(0);
  }
}

