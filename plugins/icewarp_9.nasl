#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26069);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2007-5046");
  script_bugtraq_id(25708);
  script_osvdb_id(37428);

  script_name(english:"IceWarp Merak Mail Server < 9.0.0 BODY Element XSS");
  script_summary(english:"Checks version of Icewarp");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Merak Mail Server - a webmail
server for Windows and Linux.

According to its banner, the version of IceWarp installed on the
remote host fails to properly sanitize email messages before
displaying them.  If a user reads a specially crafted message, a
remote attacker could leverage this issue to inject arbitrary HTML 
and script code into a user's browser to be executed within the 
security context of the affected application.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Icewarp Merak Mail Server version 9.0.0 or later as that
reportedly resolves the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "doublecheck_std_services.nasl", "http_version.nasl");
  if ( NASL_LEVEL >= 3000 )
    script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/nntp", 119, "Services/imap", 143, "Services/www", 32000);

  script_require_keys("www/icewarp");
  exit(0);
}


include("global_settings.inc");
include("http.inc");
include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Make sure the webmail component is accessible.
http_port = get_http_port(default:32000);
if (!get_port_state(http_port)) exit(0);

banner = get_http_banner(port:http_port);
if (!banner || "IceWarp" >!< banner) exit(0);

# Try to get the version number from a banner.
ver = NULL;
service = NULL;
#
# - SMTP.
if (isnull(ver))
{
  ports = get_kb_list("Services/smtp");
  if (isnull(ports)) ports = make_list(25);

  foreach port (ports)
  {	 
    if (get_port_state(port))
    {
     banner = get_smtp_banner(port:port);
     if (banner && (" ESMTP IceWarp " >< banner || " ESMTP Merak " >< banner))
     {
       pat = " ESMTP (IceWarp|Merak) ([0-9][0-9.-]+);";
       matches = egrep(pattern:pat, string:banner);
       if (matches)
       {
         foreach match (split(matches, keep:FALSE))
         {
           item = eregmatch(pattern:pat, string:match);
           if (!isnull(item))
           {
             ver = item[2];
             service = "SMTP";
             break;
           }
         }
       }
     }
     if (isnull(ver) && !thorough_tests) exit(0);
   }  
    if (!isnull(ver)) break;
  }
}
# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110);

  foreach port (ports)
   {
    if (get_port_state(port))
    {
     banner = get_pop3_banner(port:port);
     if (banner && " POP3 " >< banner && (" IceWarp " >< banner || " Merak " >< banner))
     {
       pat = " (IceWarp|Merak) ([0-9][0-9.-]+) POP3 ";
       matches = egrep(pattern:pat, string:banner);
       if (matches)
       {
         foreach match (split(matches, keep:FALSE))
         {
           item = eregmatch(pattern:pat, string:match);
           if (!isnull(item))
           {
             ver = item[2];
             service = "POP3";
             break;
           }
          } 
        }
      }
     if (isnull(ver) && !thorough_tests) exit(0);
    }
    if (!isnull(ver)) break;
  }
}
# - IMAP.
if (isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143);
  foreach port (ports)
  {
    if (get_port_state(port))
    {
      banner = get_imap_banner(port:port);
      if (banner && " IMAP4" >< banner && (" IceWarp " >< banner || " Merak " >< banner))
      {
       pat = " (IceWarp|Merak) ([0-9][0-9.-]+) IMAP4";
       matches = egrep(pattern:pat, string:banner);
       if (matches)
       { 
         foreach match (split(matches, keep:FALSE))
         {
           item = eregmatch(pattern:pat, string:match);
           if (!isnull(item))
           {
             ver = item[2];
             service = "IMAP";
             break;
           }
         }
        }
      }
      if (isnull(ver) && !thorough_tests) exit(0);
    }
     if (!isnull(ver)) break;
  }
}

# There's a problem if the version is < 9.0.0.
if (ver && ver =~ "^[0-8]\.")
{
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if(report_verbosity)
  { 	 
   report = string(
      "\n",	
     "According to its ", service, " banner, the remote is running IceWarp Merak Mail\n",
     "Server version ", ver, "."
   );
   security_warning(port:http_port, extra:report);
   }
  else	
   security_warning(http_port);
}
