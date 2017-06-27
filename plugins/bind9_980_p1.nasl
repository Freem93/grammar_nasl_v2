#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53842);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2011-1907");
  script_bugtraq_id(47734);
  script_osvdb_id(72172);
  script_xref(name:"Secunia", value:"44416");

  script_name(english:"ISC BIND Response Policy Zones RRSIG Query Assertion Failure DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is potentially affected by a denial of service vulnerability.
This issue only affects BIND installations that use the RPZ feature
configured for RRset replacement. When RPZ is being used, a query of
type RRSIG for a name configured for RRset replacement will trigger an
assertion failure and cause the name server process to exit.

Note that Nessus has only relied on the version itself and not
attempted to determine whether the install actually uses the RPZ
feature.");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.0-P1/RELEASE-NOTES-BIND-9.8.0-P1.html");
  # https://kb.isc.org/article/AA-00460/0/CVE-2011-1907%3A-RRSIG-Queries-Can-Trigger-Server-Crash-When-Using-Response-Policy-Zones.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d67b84a");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.8.0-P1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("bind/version");

if (version =~ '^9\\.8\\.0' && version !~ '^9\\.8\\.0-P')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.8.0-P1' +
      '\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
else exit(0, 'BIND version ' + version + ' is running on UDP port 53 and thus is not affected.');
