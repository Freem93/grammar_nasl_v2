#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83299);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/07 19:44:29 $");

  script_cve_id(
    "CVE-2015-0120",
    "CVE-2015-1896",
    "CVE-2015-1898"
  );
  script_bugtraq_id(
    74021,
    74024,
    74036
  );
  script_osvdb_id(
    120176,
    120348,
    120349
  );

  script_name(english:"IBM Tivoli Storage Manager FastBack Mount 6.1.x < 6.1.11.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager FastBack running on the
remote host is 6.1.x prior to 6.1.11.1. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw exists in the mount service due to improper
    validation of user-supplied input to the
    CRYPTO_S_EncryptBufferToBuffer() function. A remote,
    unauthenticated attacker can exploit this flaw, via
    a series of specially crafted packets, to cause a
    stack-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-0120)
    
  - An overflow condition exists in the mount service due to
    improper bounds checking. A remote, unauthenticated 
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition
    or the execution of arbitrary code. (CVE-2015-1896)

  - An overflow condition exists in the mount service due to
    improper bounds checking. A remote, unauthenticated 
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition
    or the execution of arbitrary code. (CVE-2015-1898)");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21700549
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba05015b");
  # https://www-304.ibm.com/support/docview.wss?uid=swg21700536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eeecc723");
  # https://www-304.ibm.com/support/docview.wss?uid=swg21700539
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00d87e73");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack Mount 6.1.11.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

os = get_kb_item("Host/OS");

# We only care about 6.1 specifically.
if(version !~ "^6\.1(\.|$)") audit(AUDIT_NOT_LISTEN, app_name +" 6.1", port);

# If we cant determine the OS and we don't have paranoia on we do not continue
# this is probably a version so old it does not matter for these checks anyway
if(isnull(os) && report_paranoia < 2) exit(1,"Cannot determine the operating system type.");

# Only Windows targets are affected.
if("Windows" >!< os) audit(AUDIT_OS_NOT, 'Windows');

# Check for fixed version
fix = "6.1.11.1";
if(ver_compare(ver:version,fix:fix,strict:FALSE) <  0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + app_name +
      '\n  Port              : ' + port +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_hole(port:port,extra:report);
  } 
  else security_hole(port);
} 
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port);
