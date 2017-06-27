#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16281);
  script_version ("$Revision: 1.17 $");
  script_bugtraq_id(12405);
  script_osvdb_id(13318);

  script_name(english:"SmarterTools SmarterMail Attachment Upload XSS");
  script_summary(english:"Checks for the presence of SmarterMail");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to a cross-site scripting attack."
  );

  script_set_attribute(
    attribute:'description',
    value:"There are flaws in the remote SmarterMail, a web mail interface.

This version of SmarterMail is affected by a cross-site scripting
issue.  An attacker, exploiting this flaw, would be able to steal user
credentials."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to SmarterMail 2.0.0.1837 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.smartertools.com/SmarterMail/Free-Windows-Mail-Server.aspx"
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/28");
 script_cvs_date("$Date: 2016/12/09 20:54:58 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
  local_var	r, w;

  w = http_send_recv3(method:"GET", item:string(loc, "/About/frmAbout.aspx"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  r = w[2];

 if ("<title>About SmarterMail - SmarterMail</title>" >< r)
 {
  if ( egrep(pattern:"SmarterMail Professional Edition v\.([0-1]\.|2\.0\.([0-9]([0-9])?([0-9])?\.|1([0-7][0-9][0-9]\.|8([0-2][0-9]\.|3[0-6]\.))))", string:r))
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
  }
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
