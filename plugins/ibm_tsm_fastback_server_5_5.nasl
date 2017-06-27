#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89691);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2016-0212",
    "CVE-2016-0213",
    "CVE-2016-0216"
  );
  script_bugtraq_id(
    83278,
    83280,
    83281
  );
  script_osvdb_id(
    134787,
    134789,
    134789
  );

  script_name(english:"IBM Tivoli Storage Manager FastBack 5.5.x Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager FastBack running on the
remote host is 5.5.x. It is, therefore, affected by multiple
stack-based buffer overflow conditions due to improper bounds
checking. A remote attacker can exploit these, via a crafted packet,
to crash the server or execute arbitrary code with SYSTEM privileges.");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21975358
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5833512d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.12 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_fastback_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("IBM Tivoli Storage Manager FastBack Server", "Services/tsm-fastback");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_service(svc:"tsm-fastback", default:11460, ipproto:"tcp", exit_on_fail:TRUE);
app_name = "IBM Tivoli Storage Manager FastBack Server";

version = get_kb_item_or_exit(app_name + "/" + port + "/version");
if (version == "unknown")
  audit(AUDIT_UNKNOWN_APP_VER, app_name);

# We only care about 5.5 specifically. 5.5 appears to be EoL. Upgrade path is to 6.1.12
if (version !~ "^5\.5(\.|$)")
  audit(AUDIT_NOT_LISTEN, app_name + " 5.5", port);

os = get_kb_item("Host/OS");

# Only Windows targets are affected.
if (!isnull(os) && "Windows" >!< os)
  audit(AUDIT_OS_NOT, 'Windows');

# If we cant determine the OS and we don't have paranoia on we do not continue
# this is probably a version so old it does not matter for these checks anyway
if (isnull(os) && report_paranoia < 2)
  audit(AUDIT_OS_NOT, "determinable.");

# If we have reached this code, we are vulnerable.
report =
  '\n  Product           : ' + app_name +
  '\n  Port              : ' + port +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 6.1.12 ' +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
