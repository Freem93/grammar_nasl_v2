#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11394);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2001-1161");
  script_bugtraq_id(2962);
  script_osvdb_id(1887);
  script_xref(name:"CERT", value:"642239");

  script_name(english:"IBM Domino nsf File Argument XSS");
  script_summary(english:"Checks for Lotus Domino XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly IBM Lotus Domino) running on the
remote host is affected by a cross-site scripting vulnerability due to
a failure to properly sanitize user-supplied input when requesting a
'.nsf' file. A remote, unauthenticated attacker can exploit this
issue, via a crafted URL, to execute arbitrary code in a user's
browser.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/22");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 5.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("domino_db_no_password.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/domino");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/domino");
port = get_http_port(default:80);

list = get_kb_list("www/domino/" +port+ "/db/anonymous_access");
if(!isnull(list))
{
  file = list[0];
}
else
{
  list = get_kb_list("www/" +port+ "/content/extensions/nsf");
  if (!isnull(list)) file = list[0];
  else file = "/home.nsf";
}

xss = "/<img%20src=javascript:alert("+SCRIPT_NAME -".nasl"+"-"+unixtime()+")>";

r = http_send_recv3(method: "GET", item:file+xss, port:port, exit_on_fail:TRUE);

if("<img src=javascript:alert("+SCRIPT_NAME -".nasl"+"-"+unixtime()+")>" >< r[2] )
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    xss        : TRUE,  # XSS KB key
    request    : make_list(build_url(qs:file+xss, port:port)),
    output     : chomp(r[2])
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Domino", port);
