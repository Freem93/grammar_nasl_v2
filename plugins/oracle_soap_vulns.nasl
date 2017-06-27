#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(12067);
 	script_version ("$Revision: 1.25 $");
	script_cve_id("CVE-2004-2244");
	script_bugtraq_id(9703);
	script_osvdb_id(4011);

	script_name(english:"Oracle Multiple Products SOAP Message Crafted DTD Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote Oracle Database is 
affected by a denial of service vulnerability. By sending
specially crafted SOAP messages with carefully designed
XML Data Type Definitions (DTDs), it may be possible for
a remote attacker to crash the remote database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle 9.2.0.3 - http://metalink.oracle.com" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 # http://web.archive.org/web/20040602010240/http://otn.oracle.com/deploy/security/pdf/2004alert65.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?584f3017" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/02/20");
 script_cvs_date("$Date: 2016/12/07 21:08:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
script_end_attributes();


	script_summary(english: "Checks the version of the remote database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2004-2016 Tenable Network Security, Inc.");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(1,"report_paranoia < 1");

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(1,"oracle_tnslsnr KB not set.");

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
    if(ereg(pattern:".*Version (9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_warning(port);
}
