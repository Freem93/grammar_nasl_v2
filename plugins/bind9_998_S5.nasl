#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88716);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2016-1284");
  script_bugtraq_id(82807);
  script_osvdb_id(133964);

  script_name(english:"ISC BIND 9.9.8-Sx < 9.9.8-S5 REQUIRE Assertion DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of BIND 9
Supported Preview Edition running on the remote host is version
9.9.8-Sx prior to 9.9.8-S5. It is, therefore, affected by a denial of
service vulnerability due to a flaw in file rdataset.c related to
handling flag values in incoming queries when the 'nxdomain-redirect'
option is enabled. An unauthenticated, remote attacker can exploit
this, via a crafted query with the right combination of attributes,
to cause a REQUIRE assertion failure, resulting in termination of the
service.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.

Note that 9.9.8-S4 and 9.9.8-S5 are preview versions of BIND provided
exclusively to ISC Support customers.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01348");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.8-S5 or later. Alternatively, contact the
vendor regarding a patch for BIND version 9.9.8-S4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# BIND 9 Supported Preview Edition only
#  - 9.9.8-S1 through 9.9.8-S4
if (ver =~ "^9\.9\.8-S[1-4]$")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.9.8-S5' +
      '\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
