#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20978);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519");
 script_bugtraq_id(16458, 16461);
 script_osvdb_id(22844, 22845, 22846, 22848, 22849);

 script_name(english:"SPIP < 1.8.2-g Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SPIP, an open source CMS written in PHP. 

The remote version of this software is prone to SQL injection and
cross-site scripting attacks.  An attacker could send specially
crafted URL to modify SQL requests, for example, to obtain the admin
password hash, or execute malicious script code on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/423655/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jan/993" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SPIP version 1.8.2-g or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/31");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:spip:spip");
script_end_attributes();

 
 summary["english"] = "Checks for SPIP SQL injection flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

#
# the code
#

 include("global_settings.inc");
 include("http_func.inc");
 include("http_keepalive.inc");
 include("misc_func.inc");

 port = get_http_port(default:80);
 if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 if (thorough_tests) dirs = list_uniq(make_list("/spip", cgi_dirs()));
 else dirs = make_list(cgi_dirs());

 foreach dir (dirs)
 { 
  files=make_list("forum.php3", "forum.php");
  foreach file (files)
  {
        magic = rand();
	req = http_get(item:string(dir,"/",file,'?id_article=1&id_forum=-1/**/UNION/**/SELECT%20', magic, '--'), port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        if (string('value="&gt; ', magic, '" class="forml"') >< res) {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  exit(0);
	}
  }
}
