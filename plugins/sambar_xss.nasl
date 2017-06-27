#
# (C) Tenable Network Security, Inc.
#

# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: Gregory Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#


include("compat.inc");

if(description)
{
 script_id(11492);
 script_version ("$Revision: 1.22 $");

 script_bugtraq_id(7209);
  script_osvdb_id(5097,5100,5101,5102,5103,5104,5105,5106,5107,5108,5803,5804,5805,
                  5806,5807,5808,5809,5810,5811,5812,5813,5814,5815,5816,5817,5818,
                  5819,5820);
 if (NASL_LEVEL >= 2200)
 {
 }

 script_name(english:"Sambar Server Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts CGIs which are affected by cross-site
scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The Sambar web server comes with a set of CGIs are that vulnerable
to a cross-site scripting attack.

An attacker may use this flaw to steal the cookies of your web users." );
 script_set_attribute(attribute:"solution", value:
"Delete these CGIs" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/27");
 script_cvs_date("$Date: 2016/05/26 16:14:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_summary(english:"Tests for XSS attacks");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, no_xss: 1);

cgis = make_list("/netutils/ipdata.stm?ipaddr=",
		 "/netutils/whodata.stm?sitename=",
		 "/netutils/finddata.stm?user=",
		 "/isapi/testisa.dll?check1=",
		 "/cgi-bin/environ.pl?param1=",
		 "/samples/search.dll?login=AND&query=",
		 "/wwwping/index.stm?wwwsite=",
		 "/syshelp/stmex.stm?bar=456&foo=",
		 "/syshelp/cscript/showfunc.stm?func=",
		 "/syshelp/cscript/showfnc.stm?pkg=",
		 "/sysuser/docmgr/ieedit.stm?path=",
		 "/sysuser/docmgr/edit.stm?path=",
		 "/sysuser/docmgr/iecreate.stm?path=",
		 "/sysuser/docmgr/create.stm?path=",
		 "/sysuser/docmgr/info.stm?path=",
		 "/sysuser/docmgr/ftp.stm?path=",
		 "/sysuser/docmgr/htaccess.stm?path=",
		 "/sysuser/docmgr/mkdir.stm?path=",
		 "/sysuser/docmgr/rename.stm?path=",
		 "/sysuser/docmgr/search.stm?path=",
		 "/sysuser/docmgr/sendmail.stm?path=",
		 "/sysuser/docmgr/template.stm?path=",
		 "/sysuser/docmgr/update.stm?path=",
		 "/sysuser/docmgr/vccheckin.stm?path=",
		 "/sysuser/docmgr/vccreate.stm?path=",
		 "/sysuser/docmgr/vchist.stm?path=",
		 "/cgi-bin/testcgi.exe?");
		 
report = NULL;

foreach c (cgis)
{
 u = c+"<script>foo</script>";
 r = http_send_recv3(method: "GET", item: u, port:port, exit_on_fail: 1);
 if(r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2])
 {
  report = strcat(report, ' ', build_url(port: port, qs: u), '\n');
 }
}


if (strlen(report) > 0)
{
 text = "
The following Sambar default CGIs are vulnerable :

" + report;

 security_warning(port: port, extra: text);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
