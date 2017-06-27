#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(50504);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/10/04 15:39:24 $");

 script_name(english:"Web Common Credentials");
 script_summary(english:"Tests for common web credentials.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to access protected web pages by using common
credentials.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to read protected web pages by using common login and
password combinations.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure the affected web pages to use a stronger password.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright("This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "webmirror.nasl");
 script_timeout(0);
 script_require_ports("Services/www", 80);
 script_exclude_keys("global_settings/supplied_logins_only");

 exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("web_common_credentials.inc");

t = int(get_kb_item("Settings/HTTP/max_run_time"));
if (t <= 0)
{
  if (get_kb_item("Settings/disable_cgi_scanning"))
    exit(0, "Neither CGI scanning nor web app tests is enabled.");
  p = get_preference("plugins_timeout");
  if (! isnull(p)) t = int(p);
  if (t <= 0) t = 320;
}
abort_time = unixtime() + t;


port = get_http_port(default: 80, embedded: 1);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

scl = get_kb_list("www/"+port+"/content/authentication_scheme");
if (isnull(scl)) exit(0, "No protected web page on the web server on port "+port+".");

protpl = make_list();
foreach sc (make_list("basic", "digest", "ntlm"))
{
  l = get_kb_list("www/"+port+"/content/"+sc+"_auth/url/*");
  if (! isnull(l))
    protpl = make_list(protpl, l);
}

if (max_index(protpl) == 0)
 exit(1, "No supported authentication scheme on the web server on on port "+port+".");

n_err = 0; timeout = 0;

authURL = make_array();
auth_l = mk_list(nc: nc, prevl: authURL);
found = 0;

report = ''; prev_u = NULL; audit_trail = NULL;
foreach u (sort(protpl))
{
  if (u == prev_u) continue;
  prev_u = u;
  new_l = NULL;
  if (unixtime() >= abort_time)
  {
    timeout ++;
    break;
  }

  # Anti FP
  w = http_send_recv3(port: port, item: u, method:"GET", follow_redirect: 3,
    username: rand_str(), password: rand_str(), exit_on_fail: 0);
  if (isnull(w))
  {
    debug_print("GET "+ build_url(port: port, qs: u) + " failed");
    if (++ n_err >= 6) break;
    continue;
  }
  if (w[0] =~ "^HTTP/1\.[01] 200 ") continue;	# FP

  foreach i (auth_l)
  {
    w = http_send_recv3(port: port, item: u, method:"GET", follow_redirect: 3,
      username: user[i], password: pass[i], exit_on_fail: 0);
    if (isnull(w))
    {
      debug_print("GET "+ build_url(port: port, qs: u, username: user[i], password: pass[i]) + " failed");
      if (++ n_err >= 3) break;
      continue;
    }
    if (w[0] =~ "^HTTP/1\.[01] 200 ")
    {
      # nb: Avoid false positives with Tivoli Monitoring Service 
      #     Console, which returns a 200 response after a point.
      lbody = tolower(w[2]);
      if ("access violation" >< lbody || "maximum login attempts" >< lbody)
      {
        audit_trail = "Testing exceeded the maximum number of login attempts allowed by the web application at "+build_url(port:port, qs:u)+".";
        break;
      }

      authURL[u] = i;
      report = strcat(report, build_url(port: port, qs: u, username: user[i], password: pass[i]), '\n');
      found ++;
      new_l = mk_list(nc: nc, prevl: authURL);
      break;
    }
  }
  if (! isnull(new_l)) auth_l = new_l;
  if (n_err >= 6) break;
}

if (! found)
{
  if (!isnull(audit_trail))
    exit(0, audit_trail);
  if (n_err > 3)
    exit(1, "Too many errors encountered while testing the web server on port "+port+".");
  else if (timeout)
    exit(1, "Timeout encountered while testing the web server on port "+port+".");
  else
    exit(0, "No web credentials were found on the web server on port "+port+".");
}

security_hole(port: port, extra:
'\nCredentials were guessed for these resources :\n\n' + report);
