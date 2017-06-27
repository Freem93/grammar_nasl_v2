#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42468);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2009-2820");
  script_bugtraq_id(36958);
  script_osvdb_id(59854);
  script_xref(name:"Secunia", value:"37308");

  script_name(english:"CUPS < 1.4.2 kerberos Parameter XSS");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer service is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.4.2. The 'kerberos' parameter in such versions
is not properly sanitized before being used to generate dynamic HTML
content.

An attacker can leverage this issue via a combination of attribute
injection and HTTP Parameter Pollution to inject arbitrary script code
into a user's browser to be executed within the security context of
the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3367");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L590");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.([0-3]|4\.[0-1])($|[^0-9])" ||
  version =~ "^1\.4(rc|b)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.4.2\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else if (version =~ "^(1|1\.4)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
