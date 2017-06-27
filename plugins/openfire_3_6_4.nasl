#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38688);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/07/03 21:38:22 $");

  script_cve_id("CVE-2009-1595");
  script_bugtraq_id(34804);
  script_osvdb_id(54189);
  script_xref(name:"Secunia", value:"34976");

  script_name(english:"Openfire < 3.6.4 jabber:iq:auth Crafted password_change Request Password Manipulation");
  script_summary(english:"Checks version in admin login page");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
password change vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Openfire / Wildfire, an instant messaging
server supporting the XMPP protocol.

According to its version, the installation of Openfire or Wildfire
fails to verify the owner of the account before changing the password
for the account in response to an 'iq:auth' request. An authenticated
attacker can exploit this vulnerability to change the passwords for
arbitrary Openfire / Wildfire user accounts.");
  script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/community/message/190280");
  script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/issues/browse/JM-1531");
  script_set_attribute(attribute:"solution", value:"Upgrade to Openfire version 3.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:9090);

# Grab the version from the admin console's login page.
res = http_send_recv3(method:"GET", item: "/login.jsp?url=%2Findex.jsp",port:port);
if (isnull(res)) exit(0);

if (
  'id="jive-loginVersion">' >< res[2] &&
  (
    "<title>Openfire Admin Console" >< res[2] &&
    "Openfire, Version: " >< res[2]
  ) ||
  (
    "<title>Wildfire Admin Console" >< res[2] &&
    "Wildfire, Version: " >< res[2]
  )
)
{
  prod = strstr(res[2], "<title>") - "<title>";
  prod = prod - strstr(prod, " Admin Console</title>");

  ver = strstr(res[2], "fire, Version: ") - "fire, Version: ";
  if (ver) ver = ver - strstr(ver, '\n');

  # The issue was addressed in version 3.6.4 so treat any
  # versions before that as vulnerable.
  if (
    strlen(ver) && ver =~ "^([0-2]\.|3\.([0-5][^0-9]|6\.[0-3]($|[^0-9])))" &&
    prod =~ "^(Open|Wild)fire$"
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        prod, " version ", ver, " is installed on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
