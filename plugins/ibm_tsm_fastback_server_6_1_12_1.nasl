#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85254);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/13 05:39:55 $");

  script_cve_id(
    "CVE-2015-4931",
    "CVE-2015-4932",
    "CVE-2015-4933",
    "CVE-2015-4934",
    "CVE-2015-4935"
  );
  script_osvdb_id(
    125539,
    125540,
    125541,
    125542,
    125543
  );

  script_name(english:"IBM Tivoli Storage Manager FastBack 6.1.x < 6.1.12.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager FastBack running on the
remote host is 6.1.x prior to 6.1.12.1. It is, therefore, affected by
multiple stack-based buffer overflow conditions that can be exploited
by a remote attacker, using specially crafted packets, to cause a
denial of service or possibly execute arbitrary code in the SYSTEM
context :

  - User-supplied input is not properly validated when
    handling opcode 4115, resulting in a buffer overflow.
    (CVE-2015-4931)

  - User-supplied input is not properly validated when
    handling opcode 1365 in a Files Restore Agents list,
    resulting in a buffer overflow. (CVE-2015-4932)

  - User-supplied input is not properly validated when
    handling opcode 1365 in a Volume Restore Agents list,
    resulting in a buffer overflow. (CVE-2015-4933)

  - User-supplied input is not properly validated when
    handling opcode 8192, resulting in a buffer overflow.
    (CVE-2015-4934)

  - User-supplied input is not properly validated when
    handling opcode 4755, resulting in a buffer overflow.
    (CVE-2015-4935)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21961928");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-375/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-373/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-374/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-376/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-372/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.12.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

# If we can't determine the OS and we don't have paranoia on we do not continue
# this is probably a version so old it does not matter for these checks anyway
if(isnull(os) && report_paranoia < 2) exit(1,"Cannot determine the operating system type.");

# Only Windows targets are affected.
if("Windows" >!< os) audit(AUDIT_OS_NOT, 'Windows');

# Check for fixed version
fix = "6.1.12.1";
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
