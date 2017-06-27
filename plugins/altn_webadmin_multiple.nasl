#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16271);
 script_cve_id("CVE-2005-0317", "CVE-2005-0318", "CVE-2005-0319");
 script_bugtraq_id(12395);
 script_osvdb_id(13322, 13323, 13324);
 script_version ("$Revision: 1.22 $");
 name["english"] = "Alt-N WebAdmin Multiple Remote Vulnerabilities (XSS, Bypass Access)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N WebAdmin, a web interface to MDaemon
mail server.  The remote version of this software is affected by
cross-site scripting vulnerabilities due to a lack of filtering on
user-supplied input in the file 'useredit_account.wdm' and the file
'modalframe.wdm'.  An attacker may exploit this flaw to steal user
credentials. 

This software is also vulnerable to a bypass access attack in the file
'useredit_account.wdm'.  An attacker may exploit this flaw to modify
user account information. 

An attacker needs a valid email account on the server to successfully
exploit either of these issues." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/348" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebAdmin 3.0.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/28");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:webadmin");
script_end_attributes();

 
 summary["english"] = "Checks for the version of Alt-N WebAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

global_var port;
port = get_http_port(default:1000);

function check(url)
{
 local_var r, w;

 w = http_send_recv3(method:"GET", item:string(url, "/login.wdm"), port:port, exit_on_fail: 1);
 r = w[1];
 if ( egrep(pattern:'<A href="http://www\\.altn\\.com/WebAdmin/" target="_blank">WebAdmin</A> v([0-2]\\.|3\\.0\\.[0-2]).*', string:r))
  {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
