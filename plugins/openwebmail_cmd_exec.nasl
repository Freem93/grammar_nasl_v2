#
# (C) Tenable Network Security, Inc.
#

# Modified by Xue Yong Zhi(xueyong@udel.edu) to check OpenWebmail banner
#
# As for bugtrapid 6425, a successful attack requires attacker to be able 
# to put 2 files on target system.
#
# Reference: 
# [1] http://www.securityfocus.com/archive/1/300834 
# [2] http://www.securityfocus.com/archive/1/303997
# [3] http://openwebmail.org/openwebmail/download/cert/advisories/SA-02:01.txt
#


include("compat.inc");

if(description)
{
 script_id(11416);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-1385", "CVE-2002-2410");
 script_bugtraq_id(6232, 6425);
 script_osvdb_id(6654, 7100, 7101);

 script_name(english:"OpenWebMail < 1.90 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version
OpenWebMail older than 1.90. Such versions are reportedly 
affected by multiple vulnerabilities :

  - It may be possible to execute arbitrary commands with 
    super user privilges.

  - An information disclosure vulnerability could diclose
    user names." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/300834" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/303997" );
 script_set_attribute(attribute:"see_also", value:"http://openwebmail.org/openwebmail/download/cert/advisories/SA-02:01.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenWebMail 1.90 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/11/19");
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Determines the version of openwebmail");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl" );
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


foreach d (cgi_dirs())
{
  # UGLY UGLY UGLY
  res = http_send_recv3(method:"GET", item:"/openwebmail/openwebmail.pl", port:port);

  #Banner example:
  #<a href="http://openwebmail.org/openwebmail/" target="_blank">Open WebMail</a>
  #version 1.81
  # &nbsp;
 
  if("Open WebMail" >< res[2])
  {
    if(egrep(pattern:".*version.*1\.([0-7][0-9]|80|81)", string:res))
    security_hole(port);
  }
}
