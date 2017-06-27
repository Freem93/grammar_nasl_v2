#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69370);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2013-5006");
  script_bugtraq_id(61361);
  script_osvdb_id(95519);
  script_xref(name:"EDB-ID", value:"27288");

  script_name(english:"Western Digital My Net Router main_internet.php Admin Credential Disclosure");
  script_summary(english:"Tries to retrieve admin credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web server for the Western Digital My Net router identified is
affected by an information disclosure vulnerability.  The admin password
is stored in plaintext as the value for 'var pass'.  This can be found
in the source code for the 'main_internet.php' page.  An
unauthenticated, remote attacker could gain access to the login
credentials by sending a request to an affected device.

Note that in order for this issue to be exploited, UPnP and remote
administrative access must be enabled."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/132");
  script_set_attribute(attribute:"see_also", value:"http://www.wdc.com/wdproducts/updates/?family=wdfmynetn900");
  script_set_attribute(
    attribute:"solution",
    value:
"Users of N900 and N900C devices should update the firmware to version
1.07.16 or later.  For other affected devices, please refer to the
vendor for upgrade options.  Some sources suggest disabling remote
administrative access and disable UPnP as possible mitigation steps in
the event no upgrade option is available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:wdc:mynet_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080, embedded:TRUE);
url = "/main_internet.php";

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  exit_on_fail : TRUE
);

# Does it look like My Net
if (
  "<title>WESTERN DIGITAL, INC. | WIRELESS ROUTER | HOME" >!< res[2] &&
  'LoginSubmit: function' >!< res[2]
) audit(AUDIT_NOT_DETECT, "A Western Digital My Net router", port);


if ('var pass="' >< res[2])
{
  # Extract Admin password
  pass = "";
  pat = 'var pass="([^"]*)"';
  match = eregmatch(pattern:pat, string:res[2]);
  if (!isnull(match))
  {
    pass = match[1];
    # Mask all but first and last character
    pass = pass[0] + crap(data:"*", length:6) + pass[strlen(pass)-1];
  }

  if (report_verbosity > 0)
  {
    header = 'Nessus was able to verify the issue with the following URL';
    trailer = 'And was able to determine the admin password is : "'+pass+'".' +
      '\n\nNote : All but the first and last characters have been masked.';

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Western Digital My Net", build_url(port:port, qs:url));
