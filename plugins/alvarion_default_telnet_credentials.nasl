#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72236);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_osvdb_id(100728);

  script_name(english:"Alvarion Multiple Products Default Telnet Credentials");
  script_summary(english:"Checks default Alvarion telnet credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote device is using publicly known default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to log in to the remote Alvarion device using default
credentials.  These credentials are publicly known and can allow an
attacker to gain privileged access to the device."
  );
  # http://dariusfreamon.wordpress.com/2013/12/07/alvarion-breezeaccess-vl-default-credentials/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3b8882c");
  script_set_attribute(attribute:"solution", value:"Change the passwords on the default account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:alvarion:breezeaccess");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23);
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("telnet_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


product = "Alvarion device";
password = "private";
info1 = "";
info2 = "";
prompt = ">>>";

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:prompt);
if (isnull(res)) audit(AUDIT_NOT_INST, product);

send(socket:soc, data:'3\r\n');
res = recv_until(socket:soc, pattern:">");
if (isnull(res)) audit(AUDIT_NOT_INST, product);


send(socket:soc, data:password + '\r\n');
res = recv_until(socket:soc, pattern:prompt);
if (isnull(res)) audit(AUDIT_NOT_INST, product);

index = stridx(res, '\nMain Menu');
if (index != -1)
{
  first = substr(res, 0, index);
  if (!isnull(first))
  {
    info1 = first;
    info1 = "        " + str_replace(string:info1, find:'\n', replace:'\n        ');
  }
}

send(socket:soc, data:'1\r\n');
res = recv_until(socket:soc, pattern:prompt);
if (isnull(res)) audit(AUDIT_NOT_INST, product);

send(socket:soc, data:'1\r\n');
res = recv_until(socket:soc, pattern:"Press any key to return >");
if (isnull(res)) audit(AUDIT_NOT_INST, product);


index = stridx(res, '\nConsole Speed');
if (index != -1)
{
  first = substr(res, 0, index);
  if (!isnull(first))
  {
    info2 = first;
    info2 = str_replace(string:info2, find:'\n', replace:'\n        ');
  }
}

if (info1 == "" || info2 == "") audit(AUDIT_HOST_NOT, product);


if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to log in using the default Administrator password' +
    '\n' + '\'private\' and access the following device information :' +
    '\n' +
    '\n' + info1 + info2;
  security_hole(port:port, extra:report);
}
else security_hole(port);
