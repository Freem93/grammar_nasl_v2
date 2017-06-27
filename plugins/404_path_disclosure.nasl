#
# (C) Tenable Network Security, Inc.
#

# Vulnerable servers:
# Pi3Web/2.0.0
#
# References
# Date:  10 Mar 2002 04:23:45 -0000
# From: "Tekno pHReak" <tek@superw00t.com>
# To: bugtraq@securityfocus.com
# Subject: Pi3Web/2.0.0 File-Disclosure/Path Disclosure vuln
#
# Date: Wed, 14 Aug 2002 23:40:55 +0400
# From:"D4rkGr3y" <grey_1999@mail.ru>
# To:bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: new bugs in MyWebServer
#

include("compat.inc");

if(description)
{
  script_id(11714);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/13 20:59:05 $");

 # Note: the way the test is made will lead to detecting some
 # path disclosure issues which might be checked by other plugins 
 # (like #11226: Oracle9i jsp error). I have reviewed the reported
 # "path disclosure" errors from bugtraq and the following list
 # includes bugs which will be triggered by the NASL script. Some
 # other "path disclosure" bugs in webs ervers might not be triggered
 # since they might depend on some specific condition (execution
 # of a cgi, options..)
 # jfs - December 2003

  script_cve_id("CVE-2001-1372", "CVE-2002-0266", "CVE-2002-2008", "CVE-2003-0456");
  script_bugtraq_id(3341, 4035, 4261, 5054, 8075);
  script_osvdb_id(4313, 5406, 6547, 34884);
  script_xref(name:"CERT", value:"278971");
  script_xref(name:"EDB-ID", value:"21276");


  script_name(english:"Nonexistent Page (404) Physical Path Disclosure");
  script_summary(english:"Tests for a generic path disclosure vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server reveals the physical path of the webroot when a
nonexistent page is requested.

While printing errors to the output is useful for debugging
applications, this feature should be disabled on production servers.");
  # https://web.archive.org/web/20150509055227/http://archives.neohapsis.com/archives/bugtraq/2002-02/0003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3e58d0b");
  # https://web.archive.org/web/20120713111456/http://archives.neohapsis.com/archives/vulnwatch/2003-q3/0002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c4d1560");
  # https://web.archive.org/web/20120714023155/http://archives.neohapsis.com/archives/bugtraq/2002-06/0225.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b9e782");
  script_set_attribute(attribute:"solution", value:
"Upgrade the web server to the latest version. Alternatively,
reconfigure the web server to disable debug reporting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");

  script_dependencie("iis_detailed_error.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ext_list = make_list(
  "", ".", 
  ".asp", ".aspx", 
  ".html", ".htm", ".shtm", ".shtml", 
  ".jsp", ".jspx", 
  ".php", ".php3", ".php4", ".php5", ".php6", 
  ".cfm"
);

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/iis_detailed_errors"))  exit(0, "The web server listening on port "+port+" appears to be an instance of IIS that returns detailed error messages.");

foreach ext (ext_list)
{
  filename = "niet" + rand() + ext;
  url = '/' + filename;
 
  res = test_generic_path_disclosure(item: url, 
                                     method: "GET", 
                                     port: port, 
                                     filename: filename, 
                                     fetch404: TRUE, 
                                     exit_on_fail: TRUE);

  if(res) 
  {
    set_kb_item(name:"www/"+port+"/generic_path_disclosure", value:TRUE);
    exit(0);
  }
}
exit(0, "The web server listening on port " + port + " is not affected.");
