#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91123);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/30 15:22:18 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2015-4000",
    "CVE-2016-4350"
  );
  script_bugtraq_id(
    70574,
    74733,
    89557
  );
  script_osvdb_id(
    113251,
    122331,
    138001,
    138002,
    138003,
    138004,
    138005,
    138006,
    138007,
    138008,
    138009,
    138010,
    138011,
    138012,
    138013,
    138014,
    138015,
    138016,
    138017,
    138018,
    138019,
    138020,
    138021,
    143497,
    143498
  );
  script_xref(name:"ZDI", value:"ZDI-16-249");
  script_xref(name:"ZDI", value:"ZDI-16-250");
  script_xref(name:"ZDI", value:"ZDI-16-251");
  script_xref(name:"ZDI", value:"ZDI-16-252");
  script_xref(name:"ZDI", value:"ZDI-16-253");
  script_xref(name:"ZDI", value:"ZDI-16-254");
  script_xref(name:"ZDI", value:"ZDI-16-255");
  script_xref(name:"ZDI", value:"ZDI-16-256");
  script_xref(name:"ZDI", value:"ZDI-16-257");
  script_xref(name:"ZDI", value:"ZDI-16-258");
  script_xref(name:"ZDI", value:"ZDI-16-259");
  script_xref(name:"ZDI", value:"ZDI-16-260");
  script_xref(name:"ZDI", value:"ZDI-16-261");
  script_xref(name:"ZDI", value:"ZDI-16-262");
  script_xref(name:"ZDI", value:"ZDI-16-263");
  script_xref(name:"ZDI", value:"ZDI-16-264");
  script_xref(name:"ZDI", value:"ZDI-16-265");
  script_xref(name:"ZDI", value:"ZDI-16-266");
  script_xref(name:"ZDI", value:"ZDI-16-267");
  script_xref(name:"ZDI", value:"ZDI-16-268");
  script_xref(name:"ZDI", value:"ZDI-16-269");
  script_xref(name:"ZDI", value:"ZDI-16-270");
  script_xref(name:"ZDI", value:"ZDI-16-271");
  script_xref(name:"ZDI", value:"ZDI-16-272");
  script_xref(name:"CERT", value:"577193");

  script_name(english:"SolarWinds Storage Resource Monitor Profiler < 6.2.3 Multiple Vulnerabilities (Logjam) (POODLE)");
  script_summary(english:"Checks the version of Storage Resource Monitor Profiler module.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Storage Resource Monitor (SRM) Profiler
(formerly SolarWinds Storage Manager) running on the remote host is
prior to 6.2.3. It is, therefore, affected by multiple
vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - Multiple SQL injection vulnerabilities exist due to a
    failure by various servlets to properly sanitize the
    user-supplied input to their parameters. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities to inject or manipulate SQL queries
    against the back-end database, resulting in the
    disclosure or manipulation of arbitrary data
    (CVE-2016-4350).

    The following servlets are affected :

      - BackupAssociationServlet
      - BackupExceptionsServlet
      - BexDriveUsageSummaryServlet
      - DuplicateFilesServlet
      - FileActionAssignmentServlet
      - HostStorageServlet
      - NbuErrorMessageServlet
      - ProcessesServlet
      - QuantumMonitorServlet
      - ScriptServlet
      - UserDefinedFieldConfigServlet
      - WindowsEventLogsServlet
      - XiotechMonitorServlet

  - A SQL injection (SQLi) vulnerability exists in the
    RunScript.jsp script due to improper sanitization of
    user-supplied input before using it in SQL queries. An
    unauthenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end 
    database, resulting in the disclosure and manipulation
    of arbitrary data. (VulnDB 143497)

  - A path traversal vulnerability exists due to improper
    sanitization of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to disclose sensitive information.
    (VulnDB 143498)");
  #http://www.solarwinds.com/documentation/storage/storagemanager/docs/ReleaseNotes/releaseNotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edc00ceb");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds SRM Profiler version 6.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storage_manager_installed.nbin");
  script_require_ports("installed_sw/SolarWinds Storage Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

storage_mgr = "SolarWinds Storage Manager";


install = get_single_install(app_name:storage_mgr, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];
fix = "6.2.3";


if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_report_v4(extra:report, port:port, sqli:TRUE, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, storage_mgr, version, path);
