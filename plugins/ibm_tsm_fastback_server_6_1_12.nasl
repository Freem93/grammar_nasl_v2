#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84585);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/03/04 22:12:54 $");

  script_cve_id(
    "CVE-2015-1923",
    "CVE-2015-1924",
    "CVE-2015-1925",
    "CVE-2015-1929",
    "CVE-2015-1930",
    "CVE-2015-1938",
    "CVE-2015-1941",
    "CVE-2015-1942",
    "CVE-2015-1948",
    "CVE-2015-1949",
    "CVE-2015-1953",
    "CVE-2015-1954",
    "CVE-2015-1962",
    "CVE-2015-1963",
    "CVE-2015-1964",
    "CVE-2015-1965",
    "CVE-2015-1986",
    "CVE-2016-0212",
    "CVE-2016-0213",
    "CVE-2016-0216"
  );
  script_bugtraq_id(
    75444,
    75445,
    75446,
    75447,
    75448,
    75449,
    75450,
    75451,
    75452,
    75453,
    75454,
    75455,
    75456,
    75457,
    75458,
    75459,
    75461,
    83278,
    83280,
    83281
  );
  script_osvdb_id(
    122327,
    122362,
    123811,
    123812,
    123813,
    123814,
    123815,
    123816,
    123817,
    123818,
    123819,
    123820,
    123821,
    123822,
    123823,
    123824,
    123825,
    134787,
    134788,
    134789
  );

  script_name(english:"IBM Tivoli Storage Manager FastBack 6.1.x < 6.1.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager FastBack running on the
remote host is 6.1.x prior to 6.1.12. It is, therefore, affected by
multiple vulnerabilities :

  - An overflow condition exists due to improper validation
    of user-supplied input when handling opcode 1331. A
    remote, unauthenticated attacker can exploit this issue
    to cause a buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-1923)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling opcode 1329. A
    remote, unauthenticated attacker can exploit this issue
    to cause a stack-based buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2015-1924)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling opcode 1332. A
    remote, unauthenticated attacker can exploit this issue
    to cause an overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1925)

  - A buffer overflow condition exists in the
    FXCLI_OraBR_Exec_Command() function due to improper
    validation of user-supplied input. A remote,
    unauthenticated attacker can exploit this issue, via a
    specially crafted packet, to cause a stack-based buffer
    overflow, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2015-1929)

  - A buffer overflow condition exists in the
    JOB_S_GetJobByUserFriendlyString() function due to
    improper validation of user-supplied input. A remote,
    unauthenticated attacker can exploit this issue, via a
    specially crafted packet, to cause a stack-based buffer
    overflow, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2015-1930)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling opcode 1331. A
    remote, unauthenticated attacker can exploit this issue,
    via a specially crafted packet, to execute arbitrary
    commands with a system call. (CVE-2015-1938)

  - An unspecified flaw exists that occurs during the
    handling of opcode 1329. A remote, unauthenticated
    attacker can exploit this issue to gain access to
    arbitrary files. (CVE-2015-1941)

  - An unspecified flaw exists that occurs during the
    handling of opcode 1332. A remote, unauthenticated
    attacker can exploit this issue to write or execute
    arbitrary files. (CVE-2015-1942)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling opcode 1364. A
    remote, unauthenticated attacker can exploit this
    issue, via a specially crafted packet, to cause a
    stack-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-1948)

  - An unspecified flaw exists that is triggered during the
    handling of opcode 1330. A remote, unauthenticated
    attacker can exploit this issue, via specially crafted
    packet, to execute arbitrary commands with a system
    call. (CVE-2015-1949)

  - A format string flaw exists in the vsprintf() function
    due to improper sanitization of user-supplied format
    string specifiers when processing opcode 1335. A remote,
    unauthenticated attacker can exploit this issue, via a
    specially crafted packet, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1953)

  - An overflow condition exists due to improper validation
    of user-supplied input. A remote, unauthenticated
    attacker can exploit this issue to cause a stack-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1954)

  - An overflow condition exists due to improper validation
    of user-supplied input. A remote, unauthenticated
    attacker can exploit this issue to cause a stack-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1962)

  - An overflow condition exists due to improper validation
    of user-supplied input. A remote, unauthenticated
    attacker can exploit this issue to cause a stack-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1963)

  - An overflow condition exists due to improper validation
    of user-supplied input. A remote, unauthenticated
    attacker can exploit this issue to cause a stack-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1964)

  - An overflow condition exists due to improper validation
    of user-supplied input. A remote, unauthenticated
    attacker can exploit this issue to cause a stack-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1965)

  - A format string flaw exists in the vsprintf() function
    due to improper sanitization of user-supplied format
    string specifiers when processing opcode 1301. A remote,
    unauthenticated attacker can exploit this issue, via a
    specially crafted packet, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-1986)

  - Multiple stack-based buffer overflow conditions exist
    due to improper bounds checking. A remote attacker can
    exploit these, via a crafted packet, to crash the server
    or execute arbitrary code with SYSTEM privileges.
    (CVE-2016-0212, CVE-2016-0213, CVE-2016-0216)");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21959398
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc221f52");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21975358
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5833512d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.12 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

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

if (version == "unknown")
  audit(AUDIT_UNKNOWN_APP_VER, app_name);

# We only care about 6.1 specifically.
if (version !~ "^6\.1(\.|$)")
  audit(AUDIT_NOT_LISTEN, app_name +" 6.1", port);

os = get_kb_item("Host/OS");

# Only Windows targets are affected.
if (!isnull(os) && "Windows" >!< os)
  audit(AUDIT_OS_NOT, 'Windows');

# If we cant determine the OS and we don't have paranoia on we do not continue
# this is probably a version so old it does not matter for these checks anyway
if (isnull(os) && report_paranoia < 2)
  audit(AUDIT_OS_NOT, "determinable.");


# Check for fixed version
fix = "6.1.12";
if (ver_compare(ver:version,fix:fix,strict:FALSE) <  0)
{
  report =
    '\n  Product           : ' + app_name +
    '\n  Port              : ' + port +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    exit(0);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
