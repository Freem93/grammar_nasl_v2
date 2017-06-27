#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68914);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_cve_id(
    "CVE-2011-3192",
    "CVE-2011-3368",
    "CVE-2011-3607",
    "CVE-2012-0031",
    "CVE-2012-0053",
    "CVE-2013-1862"
  );
  script_bugtraq_id(49303, 49957, 50494, 51407, 51706, 59826);
  script_osvdb_id(74721, 76079, 76744, 78293, 78556, 93366);
  script_xref(name:"EDB-ID", value:"17696");
  script_xref(name:"EDB-ID", value:"17969");
  script_xref(name:"EDB-ID", value:"18221");
  script_xref(name:"EDB-ID", value:"18442");

  script_name(english:"Apache 2.0.x < 2.0.65 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.0.x running on the
remote host is prior to 2.0.65. It is, therefore, affected by several
vulnerabilities :

  - A flaw exists in the byte-range filter, making it
    vulnerable to denial of service. (CVE-2011-3192)

  - A flaw exists in 'mod_proxy' where it doesn't properly
    interact with 'RewriteRule' and 'ProxyPassMatch'
    in reverse proxy configurations. (CVE-2011-3368)

  - A privilege escalation vulnerability exists relating to
    a heap-based buffer overflow in 'ap_pregsub' function in
    'mod_setenvif' module via .htaccess file.
    (CVE-2011-3607)

  - A local security bypass vulnerability exists within
    scoreboard shared memory that may allow the child
    process to cause the parent process to crash.
    (CVE-2012-0031)

  - A flaw exists within the status 400 code when no custom
    ErrorDocument is specified that could disclose
    'httpOnly' cookies. (CVE-2012-0053)

  - A flaw exists in the 'RewriteLog' function where it
    fails to sanitize escape sequences written to log files,
    which could result in arbitrary command execution.
    (CVE-2013-1862)

Note that the remote web server may not actually be affected by these
vulnerabilities. Nessus did not try to determine whether the affected
modules are in use nor did it test for the issues themselves.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0.65");
  # https://web.archive.org/web/20130801230537/http://httpd.apache.org/security/vulnerabilities_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?366bbb5a");
  # http://mail-archives.apache.org/mod_mbox/httpd-announce/201307.mbox/%3C20130710124920.2b8793ed.wrowe@rowe-clan.net%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c309d2dd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.0.65 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache web server");

source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used
fixed_ver = '2.0.65';
if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:fixed_ver) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.65\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
