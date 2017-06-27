#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78085);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/08 15:18:26 $");

  script_cve_id("CVE-2012-1741");
  script_bugtraq_id(54492);
  script_osvdb_id(83951);

  script_name(english:"Oracle Fusion Middleware HTTP Server (July 2012 CPU)");
  script_summary(english:"Checks the version of the Oracle Fusion Middleware HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Oracle Fusion Middleware HTTP
Server installed on the remote host is affected by an unspecified flaw
in the User Administration Pages of the Enterprise Manager for Fusion
Middleware component. A remote attacker can exploit this to impact the
host's integrity or gain unauthorized access to information.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2012 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_version.nasl");
  script_require_keys("www/oracle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);

# Make sure this is Oracle.
get_kb_item_or_exit("www/"+port+"/oracle");

# Get version information from the KB.
version = get_kb_item_or_exit("www/oracle/"+port+"/version", exit_code:1);
source = get_kb_item_or_exit("www/oracle/"+port+"/source", exit_code:1);

# Check if the remote server is affected. There is a patch in the CPU
# for this version. No other versions can be patched by this CPU.
if (version != "10.1.3.5.0") audit(AUDIT_LISTEN_NOT_VULN, "Oracle Application Server", port, version);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
