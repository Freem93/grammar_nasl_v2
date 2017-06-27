#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50844);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2010-2941");
  script_bugtraq_id(44530);
  script_osvdb_id(68951, 135391);

  script_name(english:"CUPS < 1.4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is prior to 1.4.5. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists due to improper allocation
    of memory for attribute values with invalid string data
    types. A remote attacker can exploit this, via a crafted
    IPP request, to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2010-2941)

  - An overflow condition exists in the PPD compiler due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (VulnDB 135458)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=624438");
  script_set_attribute(attribute:"see_also", value:"https://www.cups.org/blog.php?L597+I60+Q");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
  version =~ "^1\.([0-3]|4\.[0-4])($|[^0-9])" ||
  version =~ "^1\.4(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.5\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.4)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
