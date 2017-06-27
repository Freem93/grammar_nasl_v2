#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47683);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/08/12 15:38:43 $");

  script_cve_id(
    "CVE-2010-0302",
    "CVE-2010-0540",
    "CVE-2010-0542",
    "CVE-2010-1748",
    "CVE-2010-2431",
    "CVE-2010-2432"
  );
  script_bugtraq_id(38510, 40889, 40897, 40943, 41126, 41131);
  script_osvdb_id(60204, 65555, 65569, 65692, 65698, 65699);
  script_xref(name:"Secunia", value:"40165");

  script_name(english:"CUPS < 1.4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.4.4. Such versions are affected by several
vulnerabilities :

  - The patch for STR #3200 / CVE-2009-3553 was not
    complete. A remote client can cause a denial of service
    by causing the CUPS server to reference an already
    freed resource. (STR #3490) (CVE-2010-0302)

  - The CUPS daemon may be vulnerable to certain cross-site
    request forgery (CSRF) attacks, e.g., malicious IFRAME
    attacks. (STR #3498) (CVE-2010-0540)

  - An unprivileged process may be able to cause the CUPS
    server to overwrite arbitrary files as the root user.
    (STR #3510) (CVE-2010-2431)

  - The CUPS daemon is vulnerable to a heap corruption
    attack as the 'textops' filter does not verify the
    results of memory allocations. It is possible this
    may lead to arbitrary code execution. (STR #3516)
    (CVE-2010-0542)

  - The CUPS daemon is vulnerable to a denial of service
    attack if compiled without HAVE_GSSAPI. (STR #3518)
    (CVE-2010-2432)

  - The CUPS daemon is vulnerable to an information
    disclosure attack as an attacker can view portions of
    uninitialized memory by a specially crafted URL.
    (STR #3577) (CVE-2010-1748)");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3490");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3498");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3510");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3516");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3518");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3577");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L596");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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
  version =~ "^1\.([0-3]|4\.[0-3])($|[^0-9])" ||
  version =~ "^1\.4(rc|b)"
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.4.4\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.4)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
