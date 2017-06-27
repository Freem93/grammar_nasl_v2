#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47760);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-0213");
  script_bugtraq_id(41730);
  script_osvdb_id(66395);
  script_xref(name:"Secunia", value:"40652");

  script_name(english:"ISC BIND 9 'RRSIG' Record Type Remote DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service 
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of BIND
suffers from a denial of service vulnerability.  The vulnerability
exists due to an error when handling requests for the 'RRSIG' record
type where the answer is not already in the cache. This can lead to
BIND entering an infinite loop generating 'RRSIG' queries to the
authoritative server.");

  script_set_attribute(attribute:"see_also", value:"http://www.isc.org/software/bind/advisories/cve-2010-0213");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.7.1-P2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/19");
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

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  exit(1, 'This plugin only runs if \'Report paranoia\' is set to \'Paranoid\'.');

ver = get_kb_item_or_exit('bind/version');

# Versions affected : 
# 9.7.1, 9.7.1-P1

if (ver =~ '^9\\.7\\.1(-P1)?$')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' +
      'Version : ' + ver + '\n' +
      'Fix     : 9.7.1-P2';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
  exit(0);
}
else exit(0, 'BIND version '+ver+' is running on port 53 and is not vulnerable.');
