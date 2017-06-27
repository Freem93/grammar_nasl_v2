#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21736);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-3147");
  script_bugtraq_id(18565);
  script_osvdb_id(26693);
  script_xref(name:"EDB-ID", value:"1987");

  script_name(english:"Hosting Controller <= 6.1 Hotfix 3.1 Authenticated User Privilege Escalation");
  script_summary(english:"Checks version of Hosting Controller");
 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that suffers from a
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Hosting
Controller on the remote host enables any authenticated user to gain
host admin privileges and view all his resellers and change their
passwords." );
 script_set_attribute(attribute:"see_also", value:"http://hostingcontroller.com/english/logs/hotfixlogv61_3_2.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.1 if necessary and apply Hotfix 3.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/20");
 script_cvs_date("$Date: 2011/03/16 13:28:04 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("hosting_controller_detect.nasl");
  script_require_ports("Services/hosting_controller");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check for Hosting Controller installs.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8887);
foreach port (ports) {
  ver = get_kb_item(string("www/", port, "/hosting_controller"));
  if (ver) {
    # nb: versions <= 6.1 hotfix 3.1 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([0-2]\.|3\.[01]))))") {
      security_warning(port);
      if (!thorough_tests) exit(0);
    }
  }
}
