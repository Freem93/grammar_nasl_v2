#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if (description) {
  script_id(18401);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1816");
  script_bugtraq_id(13797, 14289);
  script_osvdb_id(16911);

  script_name(english:"Invision Power Board Multiple Vulnerabilities (Priv Esc, SQLi");
  script_summary(english:"Checks for privilege escalation vulnerability in Invision Power Board");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Invision Power Board on the 
remote host suffers from a privilege escalation issue.  To carry out 
an attack, an authenticated user goes to delete his own group and 
moves users from that group into the root admin group.

In addition to this, the remote version of this software is prone to a
SQL injection attack that may allow an attacker to execute arbitrary
SQL statements against the remote database. 

**** If you're using Invision Power Board version 2.0.4, this may 
**** be a false positive as the fix does not update the version
**** number." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/May/647" );
  script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034355.html" );
  script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=169215" );
  script_set_attribute(attribute:"solution", value:
"Apply the patch as discussed in the forum posting above." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/30");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/28");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # nb: do a banner check; actually exploiting it requires authentication.
  ver = matches[1];

  # versions <= 2.0.4 are vulnerable.
  if (ver =~ "^([01]\.|2\.0\.[0-4][^0-9]*)")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
