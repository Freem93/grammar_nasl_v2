#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55512);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/29 18:09:14 $");

  script_name(english:"Adobe ColdFusion Remote Development Services");
  script_summary(english:"Checks if RDS is enabled and requires authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has ColdFusion RDS enabled.");
  script_set_attribute(attribute:"description", value:
"Remote Development Services (RDS) is enabled on the remote ColdFusion
server. RDS allows developers to use IDEs such as Dreamweaver to
manage applications. It is recommended that RDS be disabled for
production servers and that it be configured to require authentication
on development servers.");
  # https://helpx.adobe.com/coldfusion/kb/disabling-enabling-coldfusion-rds-production.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3483a520");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Send a request without credentials to the RDS entry point.
post = "3:STR:3:C:/STR:1:*STR:0:";

res = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : dir + "/main/ide.cfm?CFSRV=IDE&ACTION=BrowseDir_Studio",
  data         : post,
  exit_on_fail : TRUE
);

if (!res[2]) exit(0, "RDS does not appear to be enabled on port " + port + ".");

# make sure that the response actually looks like RDS
idx = stridx(res[2], ':');
if (idx == -1)audit(AUDIT_RESP_BAD, port);

num_fields = substr(res[2], 0, idx - 1);
# check for an unrealistically large number
if (strlen(num_fields) > 10)
  audit(AUDIT_RESP_BAD, port);
else
  num_fields = int(num_fields);

# -100:Unable to authenticate on RDS server using current security information. it
# appears this is the only kind of error that can be seen when performing this action
if (num_fields == -100)
{
  if ('Unable to authenticate' >< res[2])
    auth = TRUE;
  else
    audit(AUDIT_RESP_BAD, port);
}
else
{
  # if there's no error, make sure that the response looks like valid RDS
  # before claiming that RDS is working without authentication
  prev_idx = idx + 1;
  for (i = 0; i < num_fields; i++)
  {
    idx = stridx(res[2], ':', prev_idx);
    if (idx == -1) audit(AUDIT_RESP_BAD, port);

    len = substr(res[2], prev_idx, idx - 1);
    len = int(len);
    if (len < 0) audit(AUDIT_RESP_BAD, port);

    prev_idx = idx + len + 1;
  }

  if (prev_idx != strlen(res[2])) audit(AUDIT_RESP_BAD, port);

  auth = FALSE;
}
set_kb_item(name:"coldfusion/" + port + "/rds/enabled", value:TRUE);
set_kb_item(name:"coldfusion/" + port + "/rds/auth", value:auth);
set_kb_item(name:"/tmp/coldfusion/" + port + "/rds/BrowseDir_Studio", value:res[2]);

if (auth) report = '\nRDS is enabled and requires authentication.\n';
else report = '\nRDS is enabled and does not require authentication.\n';

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
