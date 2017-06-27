#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21152);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/05/26 01:50:29 $");

  script_cve_id("CVE-2006-0816");
  script_bugtraq_id(17204);
  script_osvdb_id(24053);

  script_name(english:"Orion Application Server Crafted Filename Extension JSP Script Source Disclosure");
  script_summary(english:"Checks version of Orion");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server suffers from an information disclosure
flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Orion Application Server, an application
server running on a Java2 platform.

According to its banner, the version of Orion installed on the remote
Windows host fails to properly validate filename extensions in URLs. A
remote attacker may be able to leverage this issue to disclose the
source of JSP scripts hosted by the affected application using
specially crafted requests with dot and space characters.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-11/advisory/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Orion version 2.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "smb_nativelanman.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: avoid false-positives since this is open source and there
#     are no known exploits.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


# The flaw only affects Windows hosts.
os = get_kb_item("Host/OS/smb");
if (!os || "Windows" >!< os) exit(0);

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: Orion/([01]\.|2\.0($|\.[0-6]([^0-9]|$)))", string:banner)
) security_warning(port);
