#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49777);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2010-0218", "CVE-2010-3762");
  script_bugtraq_id(43573, 45385);
  script_osvdb_id(68270, 68271);
  script_xref(name:"Secunia", value:"41654");

  script_name(english:"ISC BIND 9 9.7.2 < 9.7.2-P2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by multiple vulnerabilities :

  - A flaw exists that allows access to a cache via
    recursion even though the ACL disallows it. Note that
    this only occurs if BIND is operating as both an
    authoritative and recursive name server in the same
    view.

  - If BIND, acting as a DNSSEC validating server, has two
    or more trust anchors configured in named.conf for the
    same zone and the response for a record in that zone
    from the authoritative server includes a bad signature,
    the validating server will crash while trying to
    validate that query.");

  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.2-P2/RELEASE-NOTES-BIND-9.7.2-P2.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.7.2-P2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("bind/version");

if (version =~ '^9\\.7\\.2([^0-9\\-]|$|-P[01]([^0-9]|$))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.7.2-P2\n';
    security_warning(port:53, proto:"udp",  extra:report);
  }
  else security_warning(port:53, proto:"udp");
  exit(0);
}
else exit(0, 'BIND version ' + version + ' is running on port 53 and is not affected.');
