#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 2200) exit(0);

include("compat.inc");

if (description)
{
	script_id(14641);
 	script_version ("$Revision: 1.34 $");
	script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id(
    "CVE-2004-0637",
    "CVE-2004-0638",
    "CVE-2004-1362",
    "CVE-2004-1363",
    "CVE-2004-1364",
    "CVE-2004-1365",
    "CVE-2004-1366",
    "CVE-2004-1367",
    "CVE-2004-1368",
    "CVE-2004-1369",
    "CVE-2004-1370",
    "CVE-2004-1371"
  );
  script_bugtraq_id(
    10871,
    11091,
    11100,
    11099,
    11120
  );
  script_osvdb_id(
    9817,
    9819,
    9861,
    9865,
    9866,
    9867,
    9868,
    9869,
    9870,
    9871,
    9872,
    9873,
    9874,
    9875,
    9876,
    9877,
    9878,
    9879,
    9880,
    9881,
    9882,
    9883,
    9884,
    9885,
    9886,
    9887,
    9888,
    9889,
    9890,
    9891,
    9892,
    12743,
    12744,
    12745,
    12746,
    12747,
    12748,
    12749,
    12750,
    12752,
    14565
  );

	script_name(english: "Oracle Database Multiple Remote Vulnerabilities (Mar 2005)");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number, contains
a remote command execution vulnerability that may allow an attacker
who can execute SQL statements with certain privileges to execute
arbitrary commands on the remote host." );
 # http://web.archive.org/web/20041108030501/http://www.oracle.com/technology/deploy/security/pdf/2004alert68.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1d0c17a" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploithub_sku", value:"EH-10-031");
 script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_cwe_id(22, 94, 119, 200, 255);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
 script_end_attributes();


	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2004-2016 Tenable Network Security, Inc.");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
  if (ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-3]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-2]))", string:version)) security_hole(port);
}

