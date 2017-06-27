#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87502);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2015-8000");
  script_bugtraq_id(79349);
  script_osvdb_id(131837);

  script_name(english:"ISC BIND 9.x < 9.9.8-P2 / 9.10.x < 9.10.3-P2 Response Parsing Class Attribute Handling DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by a denial of service vulnerability due to
improper parsing of incorrect class attributes in db.c. An
unauthenticated, remote attacker can exploit this, via a malformed
class attribute, to trigger a REQUIRE assertion failure, resulting in
a denial of service condition.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01317/");
  # https://kb.isc.org/article/AA-01328/0/BIND-9.10.3-P2-Release-Notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06404c1c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.8-P2 / 9.9.8-S3 / 9.10.3-P2 or later.
Note that 9.9.8-S3 is a preview version of BIND provided exclusively
to ISC Support customers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  # 9.x < 9.9.8-P2/9.9.8-S3
  ver =~ "^9\.[0-8]\.[0-9](([ab]|beta|rc|-[PS])[0-9]*)?$" ||
  ver =~ "^9\.9\.[0-7](([ab]|beta|rc|-[PS])[0-9]*)?$" ||
  ver =~ "^9\.9\.8((([ab]|beta|rc)[0-9]*)|(-P[0-1])|(-S[0-2]))?$" ||
  # 9.10.x < 9.10.3-P2
  ver =~ "^9\.10\.[0-2](([ab]|beta|rc|-[PS])[0-9]*)?$" ||
  ver =~ "^9\.10\.3((([ab]|beta|rc)[0-9]*)|(-P[0-1]))?$"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.9.8-P2 / 9.9.8-S3 / 9.10.3-P2' +
      '\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
