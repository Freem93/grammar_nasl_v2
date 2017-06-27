#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19755);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3038");
  script_bugtraq_id(14840);
  script_osvdb_id(19418);

  name["english"] = "Hosting Controller <= 6.1 Hotfix 2.3 Information Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may give customer PHP scripts access to
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Hosting
Controller on the remote host may allow customers to use PHP scripts
to gain access to files outside of their directory, including those
belonging to other customers, resellers, or the system itself." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d705b82" );
 script_set_attribute(attribute:"see_also", value:"http://hostingcontroller.com/english/logs/hotfixlogv61_2_4.html" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix 2.4 or later for version 6.1 or set PHP's 'open_basedir'
parameter for each customer's site via the Windows registry." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/15");
 script_cvs_date("$Date: 2011/03/16 13:28:04 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  summary["english"] = "Checks for information disclosure vulnerability in Hosting Controller <= 6.1 Hotfix 2.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

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
    # nb: versions <= 6.1 hotfix 2.3 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([01]\.|2\.[0-3]))))") {
      security_warning(port);
      if (!thorough_tests) exit(0);
    }
  }
}
