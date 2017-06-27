#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17654);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-0701");
  script_bugtraq_id(12749);
  script_osvdb_id(14631);

  script_name(english:"Oracle 8i/9i Database Server UTL_FILE Traversal Arbitrary File Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by directory traversal flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Oracle on the
remote host is reportedly subject to multiple directory traversal
vulnerabilities that may allow a remote attacker to read, write, or
rename arbitrary files with the privileges of the Oracle Database
server.  An authenticated user can craft SQL queries such that they
would be able to retrieve any file on the system and potentially
retrieve and/or modify files in the same drive as the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.argeniss.com/research/ARGENISS-ADV-030501.txt" );
 # http://lists.grok.org.uk/pipermail/full-disclosure/2005-March/032273.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68b438fb" );
 # http://web.archive.org/web/20111220155337/http://www.oracle.com/technetwork/topics/security/cpu-jan-2005-advisory-129526.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f926c604" );
 script_set_attribute(attribute:"solution", value:
"Apply the January 2005 Critical Patch Update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/03/07");
 script_cvs_date("$Date: 2013/07/02 22:32:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
script_end_attributes();

 
  script_summary(english:"Checks for multiple remote directory traversal vulnerabilities in Oracle Database 8i/9i");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_family(english:"Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (
  version &&
  ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-3]))", string:version)
) security_warning(port);
