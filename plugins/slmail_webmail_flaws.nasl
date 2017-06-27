#
# (C) Tenable Network Security, Inc.
#

# Refs:
#
#  From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
#  To: <ntbugtraq@listserv.ntbugtraq.com>, <bugtraq@securityfocus.com>,
#        <vulnwatch@vulnwatch.org>
#  Subject: Multiple Vulnerabilities in SLWebmail
#  Date: Wed, 7 May 2003 18:05:18 +0100

include( 'compat.inc' );

if(description)
{
  script_id(11596);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-2003-0266", "CVE-2003-0267", "CVE-2003-0268");
  script_bugtraq_id(7511, 7513, 7514, 7524, 7527, 7528);
  script_osvdb_id(6544, 12085, 12086, 12087, 12088);

  script_name(english:"SLMail WebMail Multiple Remote Overflows");
  script_summary(english:"Determines if the remote SLWebMail server is flawed");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to multiple buffer overflows."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running a version of the SLmail
WebMail server which is vulnerable to various flaws.

These flaws may let a user to execute arbitrary code
on this host or read arbitrary files."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to the latest version of SLWebMail."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/bugtraq/2003/May/80"
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
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

no404 = get_kb_item(string("www/", port, "/no404"));
if(no404) exit(0, "The web server on port "+port+ " does not return 404 codes");

  dirx = make_list();
  foreach dir (cgi_dirs())
  {
   dirx = make_list(dirx, dir + "/SLwebmail");
  }

  foreach dir (dirx)
  {
   w = http_send_recv3(method:"GET", item:dir + "/ShowLogin.dll?Language=fr", port:port);
   if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
   res = strcat(w[0], w[1], '\r\n', w[2]);

   if('class="ContentTitle"' >< res &&
      'class="BDTitle"' >< res &&
      "Company = " >< res)
   {
    w = http_send_recv3(method:"GET", item:dir + "/ShowGodLog.dll", port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
    {
     security_hole(port);
     exit(0);
    }
   }
  }