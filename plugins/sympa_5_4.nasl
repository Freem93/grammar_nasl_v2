#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31726);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/26 16:30:03 $");

  script_cve_id("CVE-2008-1648");
  script_bugtraq_id(28539);
  script_osvdb_id(43981);
  script_xref(name:"Secunia", value:"29575");

  script_name(english:"Sympa Malformed Content-Type Header Remote DoS");
  script_summary(english:"Checks version of Sympa");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script that is prone to a denial
of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Sympa installed on the remote
host contains a flaw that causes sympa.pl to crash when sending a text
digest if it encounters a message with a malformed Content-Type
header.");
  # https://sourcesup.cru.fr/tracker/?func=detail&group_id=23&aid=3702&atid=167
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?549c5035");
  script_set_attribute(attribute:"see_also", value:"http://www.sympa.org/distribution/latest-stable/NEWS" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Sympa 5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sympa:sympa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("sympa_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  version = matches[1];
  if (version =~ "^([0-4]\.|5\.[0-3]($|[^0-9]))")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Sympa version ", version, " appears to be running on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
