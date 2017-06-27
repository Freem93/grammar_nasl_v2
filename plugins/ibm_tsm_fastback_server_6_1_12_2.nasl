#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89788);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/27 21:08:18 $");

  script_cve_id(
    "CVE-2015-8519",
    "CVE-2015-8520",
    "CVE-2015-8521",
    "CVE-2015-8522",
    "CVE-2015-8523"
  );
  script_bugtraq_id(
    84161,
    84163,
    84164,
    84166,
    84167
  );
  script_osvdb_id(
    135253,
    135254,
    135255,
    135256,
    135257
 );
  script_xref(name:"IAVB", value:"2016-B-0045");

  script_name(english:"IBM Tivoli Storage Manager FastBack 5.5.x / 6.1.x < 6.1.12.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager FastBack running on the
remote host is 5.5.x or 6.1.x prior to 6.1.12.2. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple buffer overflow conditions exist in server
    command processing due to improper bounds checking of
    user-supplied input. An unauthenticated, remote attacker
    can exploit these to cause a buffer overflow, resulting
    in a denial of service or the execution of arbitrary
    code with system privileges. (CVE-2015-8519,
    CVE-2015-8520, CVE-2015-8521, CVE-2015-8522)

  - A denial of service vulnerability exists that allows an
    unauthenticated, remote attacker to shut down the
    service via a specially crafted TCP packet.
    (CVE-2015-8523)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21975536");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.12.2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# We only care about 5.5 and 6.1
if (version !~ "^(6\.1(\.|$)|5\.5(\.|$))")
  audit(AUDIT_NOT_LISTEN, app_name +" 5.5/6.1", port);

os = get_kb_item("Host/OS");

# Only Windows targets are affected.
if (!isnull(os) && "Windows" >!< os)
  audit(AUDIT_OS_NOT, 'Windows');

# If we cant determine the OS and we don't have paranoia on we do not continue
# this is probably a version so old it does not matter for these checks anyway
if (isnull(os) && report_paranoia < 2)
  audit(AUDIT_OS_NOT, "determinable.");


# Check for fixed version
fix = "6.1.12.2";
if (ver_compare(ver:version,fix:fix,strict:FALSE) <  0)
{
  items = make_array("Product", app_name,
                     "Port", port,
                     "Installed version", version,
                     "Fixed version", fix
                  );

  order = make_list("Product", "Port", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
