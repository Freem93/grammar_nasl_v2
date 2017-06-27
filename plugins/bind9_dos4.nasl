#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17840);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2007-0494");
  script_bugtraq_id(22231);
  script_osvdb_id(31923);

  script_name(english:"ISC BIND Crafted ANY Request Response Multiple RRsets DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of BIND installed on the remote host suggests that it
suffers from a denial of service vulnerability that could be triggered
by sending a large volume of recursive queries that return multiple
RRsets in the answer section, triggering assertion checks. To be
vulnerable you need to have enabled DNSSEC validation in named.conf by
specifying trusted-keys.

Note that Nessus obtained the version by sending a special DNS request
for the text 'version.bind' in the domain 'chaos', the value of which
can be and sometimes is tweaked by DNS administrators.");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2007-0494");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.2.8, 9.3.4, 9.4.0rc1, or 9.5.0a2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencie("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("bind/version");

if (
  ver =~ "^9\.[01]\." ||                   # 9.0.x, 9.1.x
  ver =~ "^9\.2\.[0-7]" ||                 # 9.2.0 - 9.2.7 (9.2.8 next non-vulnerable)
  ver =~ "^9\.3\.[0-3]" ||                 # 9.3.0 - 9.3.3 (9.3.4 next non-vulnerable)
  ver =~ "^9\.4\.0(a[1-6]|b[1-4])$" ||     # 9.4.0a1 - 9.4.0b4 (9.4.0rc1 next non-vulnerable)
  ver =~ "^9\.5\.0a1$"                     # 9.5.0a1 (9.5.0a2 next non-vulnerable)
)
{
  security_warning(port:53, proto:"udp");
  exit(0);
}

exit(0, "The BIND version " + ver + " install is not affected.");
