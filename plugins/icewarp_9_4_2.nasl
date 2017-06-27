#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38717);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2009-1467", "CVE-2009-1468", "CVE-2009-1469");
  script_bugtraq_id(34820, 34823, 34825, 34827);
  script_osvdb_id(54226, 54227, 54228, 54229, 54230);
  script_xref(name:"Secunia", value:"34912");

  script_name(english:"IceWarp Merak WebMail Server < 9.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of IceWarp");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp WebMail Server - a webmail
server for Windows and Linux.

According to its banner, the version of IceWarp installed on the
remote host is earlier than 9.4.2.  Such versions may reportedly be
affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in the search form 
    of the web-based groupware component. (CVE-2009-1468)

  - A cross-site scripting vulnerability exists because the
    application fails to properly sanitize HTML emails. An
    attacker can exploit this flaw through the 'cleanHTML()' 
    function of the 'html/webmail/server/inc/tools.php' 
    script. (CVE-2009-1467)

  - A cross-site scripting vulnerability exists because the
    application fails to properly sanitize RSS feeds. An
    attacker can exploit this flaw through the 'cleanHTML()' 
    function of the 'html/webmail/server/inc/rss/rss.php' 
    script. (CVE-2009-1467)

  - An input validation flaw exists in the 'Forgot Password'
    function on the login page. (CVE-2009-1469)

  - A specially crafted HTTP request may allow an attacker
    to disclose the contents of PHP files. (VulnDB 54230)

An attacker could exploit these flaws to steal user-based credentials,
create arbitrary files, or possibly execute arbitrary code subject to 
the privileges of the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d50e1cd5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?590d8c68");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0b0bed");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f822a52");
  script_set_attribute(attribute:"solution", value:
"Upgrading to IceWarp 9.4.2 or later reportedly fixes the problems.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 89, 94);

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "doublecheck_std_services.nasl", "http_version.nasl");
  if ( NASL_LEVEL >= 3000)
    script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/nntp", 119, "Services/imap", 143, "Services/www", 32000);
  script_require_keys("www/icewarp");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

# Make sure the webmail component is accessible.
http_port = get_http_port(default:32000);

banner = get_http_banner(port:http_port);
if (!banner) exit(1, "No HTTP baner on port "+http_port);
if ("IceWarp" >!< banner) exit(0, "The web server on port "+http_port+" is not IceWarp");

# Try to get the version number from a banner.
ver = NULL;
service = NULL;

#
# - HTTP
if (isnull(ver))
{
  pat = "IceWarp/([0-9\.]+)";
  matches = egrep(pattern:pat, string:banner);
  
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        service = "HTTP";
        break;
      }
    }
  }
}

#
# - SMTP
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
        pat = " ESMTP (IceWarp|Merak) ([0-9\.]+);";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches))
          {
            match = chomp(match);
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

#
# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110);

  foreach port(ports)
  {
    if (get_port_state(port))
    {
      banner = get_pop3_banner(port:port);
      if (banner && " POP3 " >< banner && (" IceWarp " >< banner || " Merak" >< banner))
      {
        pat = " (IceWarp|Merak) ([0-9\.]+) POP3 ";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches))
          {
            match = chomp(match);
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

#
# - IMAP
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
        pat = " (IceWarp|Merak) ([0-9\.]+) IMAP4";
        matches = egrep(pattern:pat, string:banner);
        if (matches)
        {
          foreach match (split(matches))
          {
            match = chomp(match);
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

if (ver && ver =~ "^[0-8]\.[0-9\.]+|9\.([0-3]\.[0-9\.+]|4\.[0-1])$")
{
  set_kb_item(name:'www/'+http_port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+http_port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "According to its ", service, " banner, the remote host is running IceWarp \n",
      "Merak WebMail Server version ", ver, ".",
      "\n"
    );
    security_warning(port:http_port, extra:report);
  }
  else security_warning(http_port);
}
