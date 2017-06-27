#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58039);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/27 15:24:47 $");

  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_osvdb_id(78819);

  script_name(english:"PHP 5.3.9 'php_register_variable_ex()' Code Execution (intrusive check)");
  script_summary(english:"Checks for response to specially crafted POST requests");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP that is affected by an
arbitrary code execution vulnerability.

Specifically, the fix for the hash collision denial of service
vulnerability (CVE-2011-4885) introduces a remote code execution
vulnerability in the function 'php_register_variable_ex()' in the file
'php_variables.c'. A new configuration variable, 'max_input_vars', was
added as a part of the fix. If the number of input variables exceeds
this value and the variable being processed is an array, code
execution can occur.

Note that this script assumes the 'max_input_vars' parameter is set to
the default value of 1000, and only runs if 'Report paranoia' is set
to 'Paranoid', and 'Enable CGI scanning' is checked.");
  script_set_attribute(attribute:"see_also", value:"https://gist.github.com/1725489");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.10");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1ee2de8");
  script_set_attribute(attribute:"see_also", value:"http://svn.php.net/viewvc?view=revision&revision=323007");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

##
#
# generate name=value pairs for the POST request.
# value is set to empty.
#
# @param num        - number of pairs to generate
# @param array_var  - whether to append an array variable at the end
# @return   string in form of str1=&str2=&...strn=&
#
##
function gen_post_strs(num,array_var)
{
  local_var i, s;

  s = NULL; for(i = 0; i < num; i++) s+= i + '=&';

  # append an array variable
  if(array_var) s +='arr_name[]=arr_val';
  else          s +='plain__var=var_val';

  return s;
}

#
# MAIN
#

port = get_http_port(default:80,php:TRUE);


#
# checking for lack of response may not be reliable, so run
# the script in paranoid mode.
#
if (report_paranoia < 2) audit(AUDIT_PARANOID);


#
# get a list of php files
#
php_files = get_kb_list('www/' + port + '/content/extensions/php');
if (isnull(php_files)) exit(0, 'No PHP files were found on the web server on port '+port+'.');
php_files = make_list(php_files);

# the default value for 'max_input_vars' in php.ini is 1000
MAX_INPUT_VARS = 1000;

good_data = gen_post_strs(num:MAX_INPUT_VARS+1, array_var:FALSE);
bad_data = gen_post_strs(num:MAX_INPUT_VARS+1, array_var:TRUE);

# prevent sending HTTP GET /
http_disable_keep_alive();

#
# find a php file that will respond to a long POST
#
count = 0;
found = 0;
foreach url (php_files)
{
  res = http_send_recv3(port:port, item: url, method:'POST', data:good_data,
                         content_type:'application/x-www-form-urlencoded', exit_on_fail:FALSE);

  # dead PHP links found by webmirror.nasl are not suitable for testing
  if(! isnull(res) && res[0] =~ "^HTTP/[0-9.]+ +200")
  {
    found = 1;
    break;
  }

  # try up to 30 php files;
  # no need to test more files as IDS/IPS/firewall might have blocked
  # POST requests with a long list of string=& pairs.
  if(count++ >= 30) break;
}

if(! found)
  exit(1,'Cannot find a suitable PHP test file on the server running on port '+port+'.'+
         '\nLong POST requests may have been blocked.');


res = http_send_recv3(port:port, item: url, method:'POST', data:bad_data,
                       content_type:'application/x-www-form-urlencoded',exit_on_fail:FALSE);



#
# vulnerable server returns either no response or error response.
#
if (
  isnull(res) ||                # Apache httpd (Unix) produces Seg Fault, httpd dies and does not respond.
  res[0] =~ "^HTTP/[0-9.]+ +500" # IIS 7, php-cgi.exe dies and "HTTP 500" is returned.
)
{
  security_hole(port:port);
  exit(0);
}
#
# 1. PHP versions that do not support 'max_input_vars'.
# 2. PHP version 5.3.10 or later (patched)
# 3. vulnerable version with 'max_input_vars' > 1000
#
else
{
  if( res[0] =~ "^HTTP/[0-9.]+ +200")
  {
    exit(0, 'The PHP version used by the web server listening on port '+port+' is not affected '+
            'or its \'max_input_vars\' configuration parameter is greater than the default value '+MAX_INPUT_VARS+'.');

  }
  else exit(1, 'The web server listening on port '+port+' returned an unexpected response.');
}
