#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(16223);
  script_version("$Revision: 1.15 $");
  script_bugtraq_id(12306);
  script_osvdb_id(13056);
  script_xref(name:"Secunia", value:"13877");
  
  script_name(english:"ExBB Netsted BBcode XSS");
  script_summary(english:"Checks ExBB's version");

  script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a cross-site
scripting vulnerability."  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running ExBB, a bulletin board system written
in PHP.

According to its version number, this install of ExBB has a
persistent cross-site scripting vulnerability.  Posting a maliciously
crafted forum comment could lead to arbitrary script code execution.
A remote attacker could exploit this to steal the authentication
cookies of legitimate users."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2005/Jan/546"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"There is no known solution at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/19");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
url = string(dir, "/search.php");
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);

if( 'class=copyright>ExBB</a>' >< r[2] )
{
  line = egrep(pattern:'Powered by <a href=.* target=_blank class=copyright>ExBB</a> (0\\.|1\\.[0-8][^0-9]|1\\.9[^.]|1\\.9\\.[01][^0-9])', string:r[2]);
  if ( line ) 
  {
  security_note(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
 }
}
