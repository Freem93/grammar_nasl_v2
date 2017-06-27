#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <20030222014450.22428.qmail@www.securityfocus.com>
# From: "Gregory" Le Bras <gregory.lebras@security-corp.org>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-006] XSS & Function
#
# We don't check for all the listed BIDs since no patch has
# ever been made (ie: vulnerable to one => vulnerable to all)



include("compat.inc");

if(description)
{
 script_id(11282);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2003-1238", "CVE-2003-1370", "CVE-2003-1371");
 script_bugtraq_id(6697, 6699, 6700, 6916, 6917);
 script_osvdb_id(50552, 52891, 58499, 58500, 58501);

 script_name(english:"Nuked-Klan 1.2b Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"It is possible to execute arbitrary PHP code on the remote host using
a flaw in the 'Nuked Klan' package.  An attacker may leverage this
flaw to leak information about the remote system or even execute
arbitrary commands. 

In addition to this problem, this service is vulnerable to various
cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/265" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/278" );
 script_set_attribute(attribute:"solution", value:
"Contact the author for a patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_cvs_date("$Date: 2016/10/27 15:14:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Executes phpinfo()");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 1);

function check(loc, module)
{
 local_var	url, w, r, report;

 if (! loc && report_paranoia < 2) return;	# Might generate a FP

 url = strcat(loc, "/index.php?file=", module, "&op=phpinfo");
 w = http_send_recv3(method:"GET", item: url, port:port, exit_on_fail: 1);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("allow_call_time_pass_reference" >< r){
        report = string(
          "A vulnerable instance of Nuke Clan can be found at the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
 	security_warning(port:port, extra:report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
}

dirs = list_uniq(make_list("/nuked-clan", "/clan-nic", "/klan", "/clan", cgi_dirs()));


foreach dir (dirs)
{
 check(loc:dir, module:"News");
 #check(loc:dir, module:"Team");
 #check(loc:dir, module:"Lien");
}
