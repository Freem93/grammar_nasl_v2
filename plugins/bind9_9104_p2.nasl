#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92493);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:32 $");

  script_cve_id("CVE-2016-2775");
  script_osvdb_id(141681);
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"ISC BIND 9.x < 9.9.9-P2 / 9.10.x < 9.10.4-P2 / 9.11.0a3 < 9.11.0b2 lwres Query DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND running on the remote name server is 9.x prior to 9.9.9-P2,
9.10.x prior to 9.10.4-P2, or 9.11.0a3 prior to 9.11.0b2. It is,
therefore, affected by an error in the lightweight resolver (lwres)
protocol implementation when resolving a query name that, when
combined with a search list entry, exceeds the maximum allowable
length. An unauthenticated, remote attacker can exploit this to cause
a segmentation fault, resulting in a denial of service condition. This
issue occurs when lwresd or the the named 'lwres' option is enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01393");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.9.8-P3 / 9.9.8-S4 / 9.10.3-P3 or later.

Note that BIND 9 version 9.9.9-S3 is available exclusively for
eligible ISC Support customers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied

fix = '';
port = 53;

if (
  ver =~ '^9\\.[0-8]([^0-9]|$)' ||
  ver =~ '^9\\.9\\.[0-8]([^0-9]|$)' ||
  ver =~ '^9\\.9\\.9($|[^0-9\\-]|-P[0-1]([^0-9]|$))'
) fix = '9.9.9-P2';
else if (
  ver =~ '^9\\.10\\.[0-3]([^0-9]|$)' ||
  ver =~ '^9\\.10\\.4($|[^0-9\\-]|-P[0-1]([^0-9]|$))'
) fix = '9.10.4-P2';
else if (
  # checking a3-a9 to be safe. a3 is the latest that could be found
  ver =~ '^9\\.11\\.0a[3-9]$' ||
  ver =~ '^9\\.11\\.0b[0-1]$'
) fix = "9.11.0b2";

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, proto:"udp", extra:report);
  }
  else security_warning(port:port, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", port, ver, "UDP");
