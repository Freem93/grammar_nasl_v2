#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69301);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id(
    "CVE-2005-3352",
    "CVE-2006-5752",
    "CVE-2007-3847",
    "CVE-2007-5000",
    "CVE-2007-6388",
    "CVE-2008-2364",
    "CVE-2010-0425",
    "CVE-2010-0434",
    "CVE-2010-2068",
    "CVE-2011-0419",
    "CVE-2011-3348",
    "CVE-2012-2687"
  );
  script_bugtraq_id(
    15834,
    24645,
    25489,
    26838,
    27237,
    29653,
    38494,
    40827,
    47820,
    49616,
    55131
  );
  script_osvdb_id(
    21705,
    37051,
    37052,
    38630,
    39133,
    39134,
    40262,
    46085,
    62674,
    62675,
    65654,
    73383,
    73388,
    75647,
    84818
  );
  script_xref(name:"CERT", value:"280613");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities");
  script_summary(english:"Checks version of Oracle HTTP Server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of Oracle HTTP Server installed on
the remote host is potentially affected by multiple vulnerabilities. 

Note that Nessus did not verify if patches or workarounds have been
applied."
  );
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d601a70e");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=45348489407964&id=1548709.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e9008fd");
  # https://support.oracle.com/epmos/faces/ui/patch/PatchDetail.jspx?patchId=16802903
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ab0c223");
  script_set_attribute(attribute:"solution", value:"Apply the July 2013 CPU.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 200, 399);
script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_version.nasl");
  script_require_keys("www/oracle", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

port = get_http_port(default:80);

# Make sure this is Oracle.
get_kb_item_or_exit("www/"+port+"/oracle");

# Get version information from the KB.
version = get_kb_item_or_exit("www/oracle/"+port+"/version", exit_code:1);
source = get_kb_item_or_exit("www/oracle/"+port+"/source", exit_code:1);

# Check if the remote server is affected. There is a patch in the CPU
# for this version. No other versions can be patched by this CPU.
if (version != "10.1.3.5.0")
audit(AUDIT_LISTEN_NOT_VULN, "Oracle Application Server", port, version);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
