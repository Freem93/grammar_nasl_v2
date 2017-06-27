#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34336);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-2831");
  script_bugtraq_id(31483);
  script_osvdb_id(48636);
  script_xref(name:"Secunia", value:"32062");

  script_name(english:"MailMarshal Spam Quarantine Management (SQM) Multiple Component XSS");
  script_summary(english:"Checks version in SMTP banner");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailMarshal SMTP, a mail server for
Windows. 

The Spam Quarantine Management web component included with the version
of MailMarshal SMTP installed on the remote host is affected by a
persistent cross-site scripting vulnerability in its 'delegated spam
management' feature.  By exploiting this issue, it may be possible for
an internal user to install a malicious program on another internal
user's (victim) computer, steal session cookies, or launch similar
attacks. 

Successful exploitation would require a victim to accept an email
invitation for delegated spam management from an attacker." );
 script_set_attribute(attribute:"see_also", value:"http://www.marshal.com/kb/article.aspx?id=12175" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailMarshal SMTP 6.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/03");
 script_cvs_date("$Date: 2011/03/11 20:59:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/smtp", 25, "Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("smtp_func.inc");

# Grab the version from the SMTP banner.

port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);

ver = NULL;
banner = get_smtp_banner(port:port);

if (banner && " ESMTP MailMarshal (v" >< banner && ") Ready" >< banner)
 {
  ver  = strstr(banner,"ESMTP MailMarshal (v") - "ESMTP MailMarshal (v" -  ") Ready"; 
  ver = chomp(ver); 
 }

if(isnull(ver) || !ereg(pattern:"^([0-9][0-9.]+)", string:ver)) 
 exit(0);

v = split(ver, sep:".",keep:FALSE);

for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

# If it's a vulnerable version...
# 6.0.3.8 to 6.3.0.0

if (
    (v[0] == 6 && v[1] == 0 && v[2]  > 3) 	       ||
    (v[0] == 6 && v[1] == 0 && v[2] == 3 && v[3] >= 8) ||
    (v[0] == 6 && v[1]  < 3 && v[1]  > 0)  	       ||
    (v[0] == 6 && v[1] == 3 && v[2] == 0 && v[3] == 0)
   )
{
  report = NULL;

  # If we're being paranoid, just flag it as vulnerable.
  if (report_paranoia > 1)
    report = string(
      "\n",
      "According to its SMTP banner, version ", ver, " of MailMarshal is\n",
      "installed on the remote host, but Nessus did not check whether the\n",
      "optional Spam Quarantine component is installed because of the Report\n",
      "Paranoia setting in effect when this scan was run.\n"
    );

  # Otherwise, make sure the affected component is installed.
  else 
   {
      port = get_http_port(default:80);
      if (!can_host_asp(port:port)) exit(0);

      foreach dir (list_uniq(make_list("", cgi_dirs())))
      {
      url = string(dir, "/SpamConsole/");
      r = http_send_recv3(method: 'GET', item:url, port:port);
      if (isnull(r)) exit(0);

      # If we can't access because of insufficient credentials...report
      if ( "You do not have permission to view this directory or page using the credentials" >< r[2])
      {
        report = string(
          "\n",
          "According to its SMTP banner, version ", ver, " of MailMarshal is\n",
          "installed on the remote host and the affected component is accessible\n",
          "under the directory /SpamConsole/. \n"
        );
	break;
      }
      }
   }
     
  if (report) 
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity) security_note(port:port, extra:report);
    else security_note(port);	
  }
}
